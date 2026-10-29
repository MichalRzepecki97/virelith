"""Explainable static PE observations, not malware classifications."""
from __future__ import annotations

EXPLANATIONS = {
    "pe_section_wx": (
        "Writable and executable section",
        "The section permits writing and executing code. This can be legitimate, "
        "but it weakens the separation between data and executable memory.",
        "Inspect section permissions and the program's expected runtime behavior.",
    ),
    "pe_section_high_entropy": (
        "High-entropy section",
        "The section has a high byte-distribution entropy. Compression, packing, "
        "encryption and ordinary embedded data can all cause this.",
        "Inspect the section content and compare with known-good builds.",
    ),
}


def explain_pe_signals(heuristics: dict | None) -> list[dict]:
    """Provide descriptions only for observations actually produced by the engine."""
    if not isinstance(heuristics, dict) or heuristics.get("status") != "evaluated":
        return []
    output = []
    for signal in (heuristics.get("signals") or [])[:96]:
        if not isinstance(signal, dict):
            continue
        signal_id = signal.get("id")
        if signal_id not in EXPLANATIONS:
            continue
        title, meaning, next_step = EXPLANATIONS[signal_id]
        output.append({
            "id": signal_id,
            "title": title,
            "level": signal.get("level", "informational"),
            "section": str(signal.get("section", ""))[:64],
            "meaning": meaning,
            "next_step": next_step,
            "interpretation": "Static observation — not proof of malware",
        })
    return output


# Explicit, bounded review of import-table APIs. These are capability hints,
# not evidence that the program calls the functions at runtime.
API_GROUPS = (
    {
        "id": "api_process_memory",
        "title": "Cross-process memory access imports",
        "apis": {"OpenProcess", "ReadProcessMemory", "WriteProcessMemory",
                 "VirtualAllocEx", "VirtualProtectEx"},
        "meaning": "These imported APIs can access or manipulate another process. "
                   "Debuggers, assistive tools and legitimate agents also use them.",
        "next_step": "Inspect call sites and the intended process-access workflow.",
    },
    {
        "id": "api_remote_thread",
        "title": "Remote execution-related imports",
        "apis": {"CreateRemoteThread", "CreateRemoteThreadEx",
                 "NtCreateThreadEx", "QueueUserAPC"},
        "meaning": "These imports can participate in cross-thread execution. "
                   "An import alone does not establish code injection.",
        "next_step": "Correlate call sites with process handles and memory operations.",
    },
    {
        "id": "api_persistence",
        "title": "Service or scheduled task management imports",
        "apis": {"CreateServiceA", "CreateServiceW", "ChangeServiceConfigA",
                 "ChangeServiceConfigW", "StartServiceA", "StartServiceW"},
        "meaning": "These APIs can install or modify Windows services, "
                   "including legitimate maintenance services.",
        "next_step": "Check service names, executable paths and authorization.",
    },
)


def explain_imports(pe_analysis: dict | None) -> list[dict]:
    """Explain matched PE import names. Never infer runtime behavior or maliciousness."""
    if not isinstance(pe_analysis, dict) or pe_analysis.get("status") != "analyzed":
        return []
    entries = pe_analysis.get("imports")
    if not isinstance(entries, list):
        return []
    imports = set()
    for entry in entries[:256]:
        if not isinstance(entry, dict) or not isinstance(entry.get("functions"), list):
            continue
        for function in entry["functions"][:1024]:
            if isinstance(function, str) and len(function) <= 128:
                imports.add(function)
    explanations = []
    for group in API_GROUPS:
        matches = sorted(imports.intersection(group["apis"]))
        if matches:
            explanations.append({
                "id": group["id"],
                "title": group["title"],
                "level": "informational",
                "matched_imports": matches,
                "meaning": group["meaning"],
                "next_step": group["next_step"],
                "interpretation": "Import-table observation — not proof of API execution or malware",
            })
    return explanations


def explain_structure(pe_analysis: dict | None) -> list[dict]:
    """Explain bounded structural facts from successfully parsed PE metadata."""
    if not isinstance(pe_analysis, dict) or pe_analysis.get("status") != "analyzed":
        return []
    output = []
    if pe_analysis.get("entry_point_in_section") is False:
        output.append({
            "id": "pe_entry_outside_sections", "title": "Entry point outside mapped sections",
            "level": "review", "meaning": "The PE entry-point RVA does not fall in any reported section. "
            "Some protected or unusual binaries can have unconventional layouts.",
            "next_step": "Inspect PE headers, section mappings and loader behavior.",
            "interpretation": "Structural observation — not proof of malware",
        })
    for finding in (pe_analysis.get("findings") or [])[:96]:
        if not isinstance(finding, dict) or finding.get("type") != "zero_raw_executable_section":
            continue
        output.append({
            "id": "pe_zero_raw_exec", "title": "Executable section has no raw file bytes",
            "level": "informational", "section": str(finding.get("section", ""))[:64],
            "meaning": "The section is marked executable but has zero raw file size. "
            "This may be a legitimate uninitialized or specially mapped section.",
            "next_step": "Compare virtual size, mapped permissions and expected compiler output.",
            "interpretation": "Structural observation — not proof of malware",
        })
    return output
