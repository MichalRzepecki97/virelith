"""Tests use synthetic metadata, not live malware."""
from virelith.heuristic_engine import evaluate_heuristics


def test_non_pe_is_not_applicable():
    assert evaluate_heuristics({"status": "not_pe"})["status"] == "not_applicable"


def test_benign_metadata_has_no_signals():
    report = evaluate_heuristics({"status": "analyzed", "sections": [
        {"name": ".text", "writable": False, "executable": True,
         "entropy": 5.8, "raw_size": 4096}
    ]})
    assert report["signals"] == []
    assert report["review_recommended"] is False


def test_writable_executable_requires_review():
    report = evaluate_heuristics({"status": "analyzed", "sections": [
        {"name": ".odd", "writable": True, "executable": True,
         "entropy": 5.0, "raw_size": 2048}
    ]})
    assert [s["id"] for s in report["signals"]] == ["pe_section_wx"]
    assert report["review_recommended"] is True


def test_high_entropy_is_informational():
    report = evaluate_heuristics({"status": "analyzed", "sections": [
        {"name": ".packed", "writable": False, "executable": False,
         "entropy": 7.8, "raw_size": 4096}
    ]})
    assert report["signals"][0]["level"] == "informational"
    assert report["review_recommended"] is False


def test_invalid_sections_report_error():
    assert evaluate_heuristics({"status": "analyzed", "sections": None})["status"] == "error"
