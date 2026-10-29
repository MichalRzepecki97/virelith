"""Imported API explanations are bounded, factual and nonverdict."""
from virelith.insight import explain_imports


def test_api_groups_only_when_imported():
    result = explain_imports({"status": "analyzed", "imports": [
        {"dll": "KERNEL32.dll", "functions": ["OpenProcess", "WriteProcessMemory"]},
        {"dll": "ADVAPI32.dll", "functions": ["CreateServiceW"]},
    ]})
    assert [r["id"] for r in result] == ["api_process_memory", "api_persistence"]
    assert result[0]["matched_imports"] == ["OpenProcess", "WriteProcessMemory"]
    assert all("not proof" in r["interpretation"] for r in result)


def test_no_claims_when_no_evidence():
    assert explain_imports(None) == []
    assert explain_imports({"status": "error", "imports": [
        {"functions": ["CreateRemoteThread"]}
    ]}) == []
    assert explain_imports({"status": "analyzed", "imports": [
        {"dll": "KERNEL32.dll", "functions": ["GetTickCount", "CloseHandle"]}
    ]}) == []


def test_invalid_imports_are_ignored():
    assert explain_imports({"status": "analyzed", "imports": [
        {"functions": "CreateRemoteThread"}, None, {"functions": [None, 1]}
    ]}) == []
