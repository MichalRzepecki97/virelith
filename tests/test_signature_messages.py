"""Friendly explanations and preserved diagnostics for signature management."""
from virelith.signature_messages import explain_freshclam, explain_yara


def test_permission_failure_is_actionable_without_raw_log_in_summary():
    log = "ERROR: Can't open log file /var/log/clamav/freshclam.log: Permission denied"
    message, details = explain_freshclam(2, log)
    assert "permissions" in message.lower()
    assert "/var/log/" not in message
    assert details == log


def test_success_does_not_claim_database_updated():
    message, _ = explain_freshclam(0, "ClamAV database is up-to-date")
    assert "finished successfully" in message
    assert "updated successfully" not in message


def test_timeout_and_missing_tool():
    assert "time limit" in explain_freshclam(-9, timed_out=True)[0]
    assert "installed" in explain_freshclam(None, failed_to_start=True)[0]


def test_yara_states_are_human_readable():
    message, _ = explain_yara({"status": "bundled_test_rules", "detail": "testing"})
    assert "bundled test rules" in message
    assert "production detection set" in message
    message, details = explain_yara({
        "status": "active", "version": "1.2.3", "sha256": "a" * 64,
        "path": "/tmp/rules.yar", "detail": "hash ok"})
    assert "version 1.2.3" in message
    assert "publisher identity" in message
    assert "/tmp/rules.yar" in details
