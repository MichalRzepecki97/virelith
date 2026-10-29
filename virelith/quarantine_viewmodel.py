"""Presentation helpers for the read-only quarantine inventory."""
from pathlib import Path

def summarize_quarantine(entries: list[dict]) -> dict:
    return {
        "total": len(entries),
        "quarantined": sum(e.get("state") == "quarantined" for e in entries),
        "restored": sum(e.get("state") == "restored" for e in entries),
    }

def filter_quarantine(entries: list[dict], query: str = "", state: str = "all") -> list[dict]:
    if state not in {"all", "quarantined", "restored"}:
        raise ValueError("invalid quarantine filter")
    needle = query.strip().casefold()
    return [e for e in entries
            if (state == "all" or e.get("state") == state)
            and (not needle or needle in str(e.get("original", "")).casefold()
                 or needle in str(e.get("id", "")).casefold())]

def quarantine_row(entry: dict) -> tuple[str, str, str]:
    return (Path(str(entry.get("original", ""))).name or "Unknown file",
            str(entry.get("state", "unknown")).replace("_", " ").title(),
            str(entry.get("created_utc", "")))
