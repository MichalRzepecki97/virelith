"""FreshClam service detection is read-only, safe, and bounded."""
from unittest.mock import patch
from virelith.signature_management import freshclam_service_status


def test_active_service_detected_without_privileges():
    with patch("virelith.signature_management.sys.platform", "linux"), \
         patch("virelith.signature_management.shutil.which", return_value="/usr/bin/systemctl"), \
         patch("virelith.signature_management.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = "active\n"
        result = freshclam_service_status()
    assert result["status"] == "active"
    assert run.call_args.args[0] == ["systemctl", "is-active", "clamav-freshclam.service"]
    assert run.call_args.kwargs["timeout"] == 3


def test_inactive_service_is_not_claimed_active():
    with patch("virelith.signature_management.sys.platform", "linux"), \
         patch("virelith.signature_management.shutil.which", return_value="/usr/bin/systemctl"), \
         patch("virelith.signature_management.subprocess.run") as run:
        run.return_value.returncode = 3
        run.return_value.stdout = "inactive\n"
        assert freshclam_service_status()["status"] == "inactive"


def test_service_check_unavailable_off_linux():
    with patch("virelith.signature_management.sys.platform", "win32"):
        assert freshclam_service_status()["status"] == "unavailable"
