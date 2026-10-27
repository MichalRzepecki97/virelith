"""Conservative explainable heuristic signals for static PE analysis.

Signals are triage hints, never confirmations of malware.
"""
from __future__ import annotations


def evaluate_heuristics(pe_analysis: dict | None) -> dict:
    """Derive bounded informational observations from PE analysis."""
    if not isinstance(pe_analysis, dict) or pe_analysis.get("status") != "analyzed":
        return {"status": "not_applicable", "signals": [], "review_recommended": False}

    signals: list[dict] = []
    sections = pe_analysis.get("sections", [])
    if not isinstance(sections, list):
        return {"status": "error", "signals": [], "review_recommended": False,
                "detail": "invalid section data"}

    for section in sections[:96]:
        if not isinstance(section, dict):
            continue
        name = str(section.get("name", ""))[:64]
        if section.get("writable") is True and section.get("executable") is True:
            signals.append({
                "id": "pe_section_wx",
                "section": name,
                "level": "review",
                "reason": "Section allows both writing and execution",
            })
        entropy = section.get("entropy")
        raw_size = section.get("raw_size")
        if (isinstance(entropy, (int, float)) and not isinstance(entropy, bool)
                and isinstance(raw_size, int) and not isinstance(raw_size, bool)
                and raw_size >= 1024 and 7.2 <= entropy <= 8):
            signals.append({
                "id": "pe_section_high_entropy",
                "section": name,
                "level": "informational",
                "reason": "High entropy may indicate compression, packing or encryption",
            })

    # Signal-based triage only; no malware probability or arbitrary score.
    return {
        "status": "evaluated",
        "signals": signals,
        "review_recommended": any(s["level"] == "review" for s in signals),
    }
