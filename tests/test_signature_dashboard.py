"""ClamAV and YARA management status is evidence-based."""
from pathlib import Path
from unittest.mock import patch

from virelith.signature_management import yara_store_snapshot


def test_unconfigured_store_is_not_claimed_signed():
    state = yara_store_snapshot("")
    assert state["status"] == "bundled_test_rules"
    assert "testing" in state["detail"].lower()


def test_missing_store_is_invalid(tmp_path: Path):
    state = yara_store_snapshot(str(tmp_path / "missing"))
    assert state["status"] == "invalid"


def test_active_store_uses_verified_metadata_only(tmp_path: Path):
    metadata = {
        "source": "signed_store", "version": "2.3.1",
        "sha256": "a" * 64, "path": "/tmp/rules.yar",
    }
    with patch("virelith.active_rules.load_active_rules", return_value=("rule ok { condition: true }", metadata)):
        state = yara_store_snapshot(str(tmp_path))
    assert state["status"] == "active"
    assert state["version"] == "2.3.1"
    assert "does not revalidate" in state["detail"]
