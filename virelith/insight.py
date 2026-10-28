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
