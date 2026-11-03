"""Operator-facing signature status messages.

Diagnostics are deliberately kept separate from the user-facing explanation.
"""
from __future__ import annotations


def explain_freshclam(exit_code: int | None, output: str = "", *,
                      timed_out: bool = False, failed_to_start: bool = False) -> tuple[str, str]:
    """Return (friendly status, raw diagnostics), never falsely claim updated."""
    detail = str(output)[-6000:]
    lowered = detail.lower()
    if timed_out:
        return ("Update stopped — time limit reached. No update was verified. "
                "Try again later or check FreshClam configuration.", detail)
    if failed_to_start:
        return ("FreshClam could not be started. Check that it is installed "
                "and available on the system PATH.", detail)
    if exit_code == 0:
        return ("FreshClam finished successfully. Check the database status "
                "to see which signature files are installed.", detail)
    if any(word in lowered for word in ("permission denied", "operation not permitted", "access denied")):
        return ("Update blocked by file permissions. FreshClam cannot access "
                "its log or database directory. Check permissions or your "
                "system's FreshClam service configuration.", detail)
    if any(word in lowered for word in ("locked", "lock file", "another freshclam", "resource temporarily unavailable")):
        return ("Update could not start because the signature database is in use. "
                "Check whether a FreshClam service is already running.", detail)
    if any(word in lowered for word in ("rate limit", "429", "403", "temporarily unavailable")):
        return ("The update server refused or delayed the request. "
                "Check FreshClam configuration and retry later.", detail)
    return ("Signature update failed. The existing database has not been "
            "confirmed as updated. Open technical details for the cause.", detail)


def explain_yara(state: dict) -> tuple[str, str]:
    status = state.get("status")
    if status == "active":
        return (f"Active rule set verified locally — version {state.get('version', '?')}. "
                "This checks integrity, not publisher identity.",
                f"Path: {state.get('path', '?')}\nSHA-256: {state.get('sha256', '?')}\n"
                + str(state.get("detail", "")))
    if status == "bundled_test_rules":
        return ("No active signed rule set configured. Virelith is using "
                "bundled test rules, not a production detection set.",
                str(state.get("detail", "")))
    return ("The configured YARA rule store could not be verified. "
            "Check its path and activated rules before scanning.",
            str(state.get("detail", "")))
