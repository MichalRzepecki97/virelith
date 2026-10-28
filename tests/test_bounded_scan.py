"""Unit tests for bounded traversal; no AV engine required."""
from pathlib import Path

import pytest

from virelith.cli import ScanLimitExceeded, files_under


def test_bounded_folder_scan(tmp_path):
    (tmp_path / "b.txt").write_text("B")
    (tmp_path / "a.txt").write_text("A")
    assert [p.name for p in files_under(tmp_path)] == ["a.txt", "b.txt"]


def test_file_count_limit(tmp_path):
    for idx in range(3):
        (tmp_path / f"{idx}.txt").write_text("x")
    walk = files_under(tmp_path, max_files=2)
    assert len([next(walk), next(walk)]) == 2
    with pytest.raises(ScanLimitExceeded, match="file count"):
        next(walk)


def test_total_size_limit(tmp_path):
    (tmp_path / "big.bin").write_bytes(b"0" * (1024 * 1024 + 1))
    with pytest.raises(ScanLimitExceeded, match="total input size"):
        list(files_under(tmp_path, max_total_mb=1))


def test_depth_limit(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "file").write_text("x")
    with pytest.raises(ScanLimitExceeded, match="depth"):
        list(files_under(tmp_path, max_depth=0))


def test_symlink_skipped(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("x")
    (tmp_path / "link.txt").symlink_to(target)
    assert list(files_under(tmp_path)) == [target]
    with pytest.raises(ValueError, match="Symlink"):
        list(files_under(tmp_path / "link.txt"))


def test_empty_directory(tmp_path):
    assert list(files_under(tmp_path)) == []
