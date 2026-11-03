# FreshClam on Kali: service-managed versus manual updates

Virelith should not manage system privileges or change ownership of ClamAV's
log/database directories. Its Settings page detects whether the systemd unit
`clamav-freshclam.service` is active. When active, manual update is disabled
to avoid competing updater processes.

Read-only diagnostics:

```bash
systemctl is-active clamav-freshclam.service
systemctl status clamav-freshclam.service --no-pager
clamscan --version
ls -lh /var/lib/clamav/
```

If the service is active, let the operating system maintain databases. The
user can check the actual scanner and installed signature files from Virelith.

If not active, review the local FreshClam installation, configuration, logs
and permissions with system administration tools. On Kali, a manual unprivileged
`freshclam --stdout` may fail on `/var/log/clamav/freshclam.log` because that
file is owned by a service account. Do **not** run the whole desktop app as root,
`chmod 777` ClamAV directories, or assume a failure means malware detection
stopped working.

For YARA-X, the empty signed rule store input means bundled testing rules are
active. This is **not a production-grade malware signature set**. Activate
only independently verified, signed rule packages through the separate trusted
rule store workflow; the dashboard only verifies active local consistency.

Release caveats: systemd detection is Linux-specific; other platforms are
reported as unknown. Current UI doesn't support Windows-specific updater
discovery or service control.
