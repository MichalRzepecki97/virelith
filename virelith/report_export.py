"""Safe, offline exports of scan evidence. No active content in HTML."""
from __future__ import annotations
from html import escape
import json


def analysis_payload(item: dict) -> dict:
    keys = ("path", "sha256", "verdict", "clamav", "yara",
            "pe_analysis", "heuristics", "insight")
    return {key: item.get(key) for key in keys}


def export_report_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)


def export_report_html(report: dict) -> str:
    """Render untrusted report text safely as escaped, static HTML."""
    entries = report.get("files") or []
    sections = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        details = escape(json.dumps(analysis_payload(item), indent=2, ensure_ascii=False))
        title = escape(str(item.get("path", "Unknown file")))
        verdict = escape(str(item.get("verdict", "unknown")))
        sections.append(f"<section><h2>{title}</h2><p>Verdict: {verdict}</p><pre>{details}</pre></section>")
    completeness = "Complete" if report.get("complete") is not False else "Incomplete"
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<title>Virelith Scan Report</title><style>"
            "body{font:15px system-ui,sans-serif;background:#0b151b;color:#edf5f5;max-width:1100px;margin:40px auto;padding:16px}"
            "section{background:#13232b;border:1px solid #304650;border-radius:8px;padding:20px;margin:20px 0}"
            "pre{overflow-wrap:anywhere;white-space:pre-wrap;color:#bfd4da}"
            "</style></head><body><h1>Virelith Scan Report</h1>"
            f"<p>Scan status: {completeness}. This report does not prove files are safe.</p>"
            + "".join(sections) + "</body></html>")
