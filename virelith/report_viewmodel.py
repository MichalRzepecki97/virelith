"""Present scan report verdicts without confusing 'no detection' with safe."""
from __future__ import annotations


def summarize_report(report: dict) -> dict:
    files = report.get("files", [])
    if not isinstance(files, list):
        raise ValueError("invalid report files")
    counts = {"detection": 0, "no_detection": 0, "incomplete": 0, "error": 0}
    for item in files:
        verdict = item.get("verdict", "incomplete") if isinstance(item, dict) else "incomplete"
        counts[verdict if verdict in counts else "incomplete"] += 1
    status = ("Detection reported" if counts["detection"] else
              "Scan incomplete" if counts["incomplete"] or counts["error"] else
              "No detection reported")
    return {"status": status, "counts": counts, "total": len(files)}


def describe_file(item: dict) -> str:
    lines = ["Path: " + str(item.get("path", "")),
             "Verdict: " + str(item.get("verdict", "unknown")),
             "SHA-256: " + str(item.get("sha256") or "unavailable")]
    for key, title in (("clamav", "ClamAV"), ("yara", "YARA-X")):
        engine = item.get(key) or {}
        lines.append(f"{title}: {engine.get('status', 'unavailable')}")
        if engine.get("matches"):
            lines.append("  Matches: " + ", ".join(map(str, engine["matches"])))
        if engine.get("detail"):
            lines.append("  Detail: " + str(engine["detail"])[:300])
    pe = item.get("pe_analysis") or {}
    lines.append("PE analysis: " + str(pe.get("status", "unavailable")))
    if pe.get("section_count") is not None:
        lines.append("  Sections: " + str(pe["section_count"]))
    heuristics = item.get("heuristics") or {}
    lines.append("Heuristics: " + str(heuristics.get("status", "unavailable")))
    lines.append("  Review recommended: " + str(heuristics.get("review_recommended", False)))
    for signal in heuristics.get("signals") or []:
        lines.append("  Signal: " + str(signal))
    return "\n".join(lines)
