"""MVP: local on-demand scan, no quarantine, no file execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from datetime import datetime, timezone

from .pe_analyzer import analyze_pe


def scan_clamav(path: Path, exe: str) -> dict:
    try:
        completed = subprocess.run([exe, "--no-summary", str(path)], capture_output=True,
                                   text=True, timeout=180, errors="replace")
        status = {0: "no_detection", 1: "detected", 2: "error"}.get(completed.returncode, "error")
        return {"status": status, "detail": (completed.stdout + completed.stderr).strip()[-4000:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "detail": str(exc)}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def scan_yara(path: Path, compiled_rules, max_size: int) -> dict:
    try:
        if path.stat().st_size > max_size:
            return {"status": "skipped", "detail": "size limit"}
        data = path.read_bytes()
        result = compiled_rules.scan(data)
        hits = [rule.identifier for rule in result.matching_rules]
        return {"status": "detected" if hits else "no_detection", "matches": hits}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


def scan_one(path: Path, clam_exe: str, rules, max_yara_bytes: int) -> dict:
    item = {"path": str(path), "sha256": None, "clamav": None, "yara": None, "pe_analysis": None}
    try:
        item["sha256"] = sha256_file(path)
    except OSError as exc:
        item["error"] = str(exc)
        item["verdict"] = "error"
        return item
    item["pe_analysis"] = analyze_pe(path)
    item["clamav"] = scan_clamav(path, clam_exe)
    item["yara"] = scan_yara(path, rules, max_yara_bytes)
    states = {item["clamav"]["status"], item["yara"]["status"]}
    # A matching local test rule is a detection, not a proven malicious classification.
    if "detected" in states:
        item["verdict"] = "detection"
    elif states == {"no_detection"}:
        item["verdict"] = "no_detection"
    else:
        item["verdict"] = "incomplete"
    return item


def files_under(target: Path):
    if target.is_file():
        yield target
    elif target.is_dir():
        for root, _, filenames in os.walk(target):
            for name in filenames:
                yield Path(root) / name
    else:
        raise FileNotFoundError(str(target))


def main():
    parser = argparse.ArgumentParser(description="Virelith MVP local scanner")
    parser.add_argument("target", type=Path, help="file or directory")
    parser.add_argument("--clam", default="clamscan.exe" if os.name == "nt" else "clamscan")
    parser.add_argument("--rules", type=Path, default=Path(__file__).resolve().parent.parent / "rules" / "test_rule.yar")
    parser.add_argument("--report", type=Path, default=Path("scan-report.json"))
    parser.add_argument("--max-yara-mb", type=int, default=64)
    args = parser.parse_args()
    if args.max_yara_mb < 1:
        parser.error("--max-yara-mb must be >= 1")
    import yara_x
    try:
        compiled = yara_x.compile(args.rules.read_text(encoding="utf-8"))
    except Exception as exc:
        parser.error(f"Cannot compile rules: {exc}")
    results = []
    try:
        for path in files_under(args.target):
            result = scan_one(path, args.clam, compiled, args.max_yara_mb * 1024 * 1024)
            results.append(result)
            print(f"{result['verdict']:>12} {path}")
    except FileNotFoundError:
        parser.error(f"Target not found: {args.target}")
    payload = {"schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
               "target": str(args.target), "files": results}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Report: {args.report.resolve()}")
    if any(r["verdict"] == "detection" for r in results):
        return 1
    if any(r["verdict"] != "no_detection" for r in results):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
