"""Pure data transformation and filters for scan history UI."""
from pathlib import Path

def filter_scans(scans: list[dict], query: str = "", verdict: str = "all") -> list[dict]:
    if verdict not in ("all", "detections", "no_detections"):
        raise ValueError("unsupported filter")
    term = query.strip().casefold()
    return [
        scan for scan in scans
        if (not term or term in str(scan.get("target", "")).casefold()
            or term in Path(str(scan.get("target", ""))).name.casefold())
        and (verdict == "all" or (int(scan.get("detections", 0)) > 0
             if verdict == "detections" else int(scan.get("detections", 0)) == 0))
    ]
