from virelith.report_viewmodel import summarize_report, describe_file


def test_detections_take_priority():
    report = {"files": [{"verdict": "detection"}, {"verdict": "incomplete"}]}
    assert summarize_report(report)["status"] == "Detection reported"


def test_no_detection_does_not_claim_safe():
    assert summarize_report({"files": [{"verdict": "no_detection"}]})["status"] == "No detection reported"


def test_error_is_incomplete():
    assert summarize_report({"files": [{"verdict": "error"}]})["status"] == "Scan incomplete"


def test_file_details_show_engines():
    details = describe_file({"path": "hello.exe", "sha256": "123",
        "verdict": "detection", "clamav": {"status": "no_detection"},
        "yara": {"status": "detected", "matches": ["TestRule"]}})
    assert "YARA-X: detected" in details
    assert "TestRule" in details
