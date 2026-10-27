"""Safe PE-analyzer tests; no malicious samples required."""
from pathlib import Path

from virelith.pe_analyzer import _entropy, analyze_pe


def test_entropy_extremes():
    assert _entropy(b"") == 0
    assert _entropy(b"A" * 4096) == 0
    assert round(_entropy(bytes(range(256))), 5) == 8.0


def test_text_is_not_pe(tmp_path: Path):
    path = tmp_path / "ordinary.txt"
    path.write_text("hello", encoding="utf-8")
    result = analyze_pe(path)
    assert result["status"] == "not_pe"
    assert result["findings"] == []


def test_size_limit(tmp_path: Path):
    path = tmp_path / "large.bin"
    path.write_bytes(b"x" * 20)
    assert analyze_pe(path, max_bytes=10)["status"] == "skipped"


def test_malformed_mz_does_not_crash(tmp_path: Path):
    path = tmp_path / "bad.exe"
    path.write_bytes(b"MZ" + b"x" * 12)
    assert analyze_pe(path)["status"] == "error"
