"""Structural PE explanations are evidence-based and fail closed."""
from virelith.insight import explain_structure


def test_structural_observations_from_verified_metadata():
    pe = {"status": "analyzed", "entry_point_in_section": False, "findings": [
        {"type": "zero_raw_executable_section", "section": ".virtual"},
        {"type": "high_section_entropy", "section": ".text"},
    ]}
    result = explain_structure(pe)
    assert [row["id"] for row in result] == ["pe_entry_outside_sections", "pe_zero_raw_exec"]
    assert all("not proof of malware" in row["interpretation"] for row in result)


def test_no_fabrication_when_not_pe_or_fields_absent():
    assert explain_structure(None) == []
    assert explain_structure({"status": "not_pe", "entry_point_in_section": False}) == []
    assert explain_structure({"status": "analyzed", "findings": []}) == []
    assert explain_structure({"status": "analyzed", "entry_point_in_section": True}) == []


def test_only_verified_zero_raw_finding_is_explained():
    assert explain_structure({"status": "analyzed", "findings": [
        {"type": "writable_executable_section", "section": ".text"},
    ]}) == []
