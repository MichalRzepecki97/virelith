from virelith.insight import explain_pe_signals


def test_explanations_only_for_real_signals():
    result = explain_pe_signals({"status": "evaluated", "signals": [
        {"id": "pe_section_wx", "section": ".text", "level": "review"},
        {"id": "pe_section_high_entropy", "section": ".data", "level": "informational"},
        {"id": "unknown", "section": "x", "level": "review"},
    ]})
    assert [item["id"] for item in result] == ["pe_section_wx", "pe_section_high_entropy"]
    assert all("not proof" in item["interpretation"] for item in result)


def test_no_explanation_for_failed_analysis():
    assert explain_pe_signals(None) == []
    assert explain_pe_signals({"status": "not_applicable", "signals": [
        {"id": "pe_section_wx"}
    ]}) == []
