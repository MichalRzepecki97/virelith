"""Offline report serialization must not execute embedded HTML."""
import json
from virelith.report_export import analysis_payload, export_report_html, export_report_json


def test_html_escapes_untrusted_file_metadata():
    report = {"complete": False, "files": [{
        "path": '<script>alert("x")</script>',
        "verdict": "<img src=x onerror=alert(1)>",
        "insight": [{"meaning": "<iframe>"}],
    }]}
    html = export_report_html(report)
    assert "<script>alert" not in html
    assert "<iframe>" not in html
    assert "&lt;script&gt;" in html
    assert "Incomplete" in html


def test_json_preserves_evidence_and_provenance():
    report = {"target": "/tmp/a.exe", "files": [{"path": "/tmp/a.exe", "sha256": "f" * 64}]}
    assert json.loads(export_report_json(report)) == report
    assert analysis_payload(report["files"][0])["sha256"] == "f" * 64
