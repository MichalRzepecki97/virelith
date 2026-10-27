"""Offline updater tests; no network traffic or executable malware."""
import hashlib
import json
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from virelith.update_manager import clamav_status, stage_yara_rules


RULE = b'rule Virelith_Test { strings: $a = "VIRELITH_MARKER" condition: $a }'


def write_inputs(tmp_path: Path, *, digest: str | None = None):
    rules = tmp_path / "source.yar"
    rules.write_bytes(RULE)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "version": "0.4.0",
        "sha256": digest or hashlib.sha256(RULE).hexdigest(),
    }), encoding="utf-8")
    return rules, manifest


def test_stages_valid_rules(tmp_path: Path):
    rules, manifest = write_inputs(tmp_path)
    result = stage_yara_rules(rules, manifest, tmp_path / "staged")
    assert result["status"] == "staged"
    assert Path(result["path"]).read_bytes() == RULE


def test_rejects_modified_rules(tmp_path: Path):
    rules, manifest = write_inputs(tmp_path, digest="0" * 64)
    assert stage_yara_rules(rules, manifest, tmp_path / "staged")["status"] == "error"


def test_rejects_version_traversal(tmp_path: Path):
    rules, manifest = write_inputs(tmp_path)
    manifest.write_text(json.dumps({
        "version": "../evil", "sha256": hashlib.sha256(RULE).hexdigest()
    }), encoding="utf-8")
    assert stage_yara_rules(rules, manifest, tmp_path / "staged")["status"] == "error"


def test_does_not_overwrite_existing_version(tmp_path: Path):
    rules, manifest = write_inputs(tmp_path)
    target = tmp_path / "staged"
    assert stage_yara_rules(rules, manifest, target)["status"] == "staged"
    assert stage_yara_rules(rules, manifest, target)["status"] == "error"


def test_clamav_status_with_database(tmp_path: Path):
    (tmp_path / "daily.cld").write_bytes(b"test")
    with patch("virelith.update_manager.subprocess.run",
               return_value=SimpleNamespace(returncode=0, stdout="ClamAV test", stderr="")):
        result = clamav_status(database_dir=tmp_path)
    assert result["status"] == "ok"
    assert result["databases"][0]["name"] == "daily.cld"


def test_clamav_status_missing_database(tmp_path: Path):
    with patch("virelith.update_manager.subprocess.run",
               return_value=SimpleNamespace(returncode=0, stdout="ClamAV test", stderr="")):
        assert clamav_status(database_dir=tmp_path)["status"] == "database_missing"
