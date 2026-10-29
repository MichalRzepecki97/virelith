"""Signature update operations must be explicit and bounded."""
from unittest.mock import patch
import pytest
from virelith.signature_management import update_clamav


def test_update_calls_freshclam_only_with_fixed_arguments():
    with patch("virelith.signature_management.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = "database is up-to-date"
        run.return_value.stderr = ""
        result = update_clamav(timeout=30)
    assert result["status"] == "completed"
    run.assert_called_once()
    args, kwargs = run.call_args
    assert args[0] == ["freshclam", "--stdout"]
    assert kwargs["timeout"] == 30
    assert kwargs["check"] is False


def test_update_failure_does_not_claim_success():
    with patch("virelith.signature_management.subprocess.run") as run:
        run.return_value.returncode = 1
        run.return_value.stdout = ""
        run.return_value.stderr = "database lock"
        result = update_clamav()
    assert result["status"] == "error"


def test_invalid_timeout():
    with pytest.raises(ValueError):
        update_clamav(timeout=0)
