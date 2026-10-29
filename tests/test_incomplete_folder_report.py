from virelith.report_viewmodel import summarize_report


def test_incomplete_folder_never_looks_clean():
    report = {"complete": False, "traversal_error": "file count limit", "files": [
        {"verdict": "no_detection"}
    ]}
    assert summarize_report(report)["status"] == "Scan incomplete"


def test_partial_scan_with_hit_still_declares_incomplete():
    report = {"complete": False, "traversal_error": "depth limit", "files": [
        {"verdict": "detection"}
    ]}
    assert summarize_report(report)["status"] == "Scan incomplete — detections present"
