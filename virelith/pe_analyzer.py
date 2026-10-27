"""Static PE metadata inspection. No execution and no malware verdicts."""
from __future__ import annotations

from collections import Counter
import math
from pathlib import Path


def _entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def analyze_pe(path: Path, *, max_bytes: int = 64 * 1024 * 1024) -> dict:
    """Inspect a PE file. A finding is an indicator, never a malware verdict.

    Only analyze files whose first two bytes are MZ. Size caps bound resource use.
    The PE parser processes untrusted input: call from a constrained worker for
    production use.
    """
    import pefile

    result = {"status": "not_pe", "sections": [], "imports": [], "findings": []}
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return {**result, "status": "skipped", "detail": "PE size limit"}
        with path.open("rb") as stream:
            if stream.read(2) != b"MZ":
                return result

        pe = pefile.PE(str(path), fast_load=True)
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            machine = int(pe.FILE_HEADER.Machine)
            result["machine"] = hex(machine)
            result["entry_point"] = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            result["section_count"] = len(pe.sections)
            for section in pe.sections:
                name = section.Name.rstrip(b"\\x00").decode("utf-8", errors="replace")
                data = section.get_data()
                entropy = round(_entropy(data), 3)
                flags = int(section.Characteristics)
                writable = bool(flags & 0x80000000)
                executable = bool(flags & 0x20000000)
                result["sections"].append({
                    "name": name,
                    "entropy": entropy,
                    "raw_size": int(section.SizeOfRawData),
                    "virtual_size": int(section.Misc_VirtualSize),
                    "writable": writable,
                    "executable": executable,
                })
                if writable and executable:
                    result["findings"].append({
                        "type": "writable_executable_section", "section": name,
                        "severity": "review",
                    })
                if entropy >= 7.2 and len(data) >= 1024:
                    result["findings"].append({
                        "type": "high_section_entropy", "section": name,
                        "severity": "informational",
                    })

            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else ""
                functions = []
                for imp in entry.imports:
                    functions.append(
                        imp.name.decode("utf-8", errors="replace")
                        if imp.name else f"ordinal:{imp.ordinal}"
                    )
                result["imports"].append({"dll": dll, "functions": functions})
            result["status"] = "analyzed"
        finally:
            pe.close()
        return result
    except (OSError, ValueError, pefile.PEFormatError) as exc:
        return {**result, "status": "error", "detail": str(exc)[:500]}
    except Exception as exc:
        # Fail closed for a malformed sample; do not interrupt the entire scan.
        return {**result, "status": "error", "detail": f"PE parser failed: {type(exc).__name__}"}
