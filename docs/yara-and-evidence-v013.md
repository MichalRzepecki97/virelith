# Virelith — signed YARA packages & history comparison

This branch adds two related evidence-management workflows.

## Signed YARA installation (offline, explicit)

1. Obtain the **publisher Ed25519 public key through an independent trusted channel**, not from the same unverified package.
2. Obtain the YARA `.yar` file, exact-byte JSON manifest
   (`{"version":"1.0.0","sha256":"..."}`) and raw 64-byte Ed25519
   signature over the **manifest's original bytes**.
3. In Settings → YARA-X, choose the four files and local rule store destination.
4. Click **Verify signature & activate rules**; verify the trust notice.
5. On success, Virelith saves that store in Settings for **future** scans.
   Previously saved scan reports are not altered.

Activation reuses `activate_signed_rules`: verifies a 32-byte separately
trusted Ed25519 key, signature, SHA-256 of YARA rules, YARA-X compilation,
monotonic package version, and local atomic current-state pointer. Do not use
the GUI to bootstrap trust from a public key shipped alongside unknown rules.
No automatic YARA downloads, no online marketplace, no arbitrary rule scripts.

**Caution:** the existing activation implementation is a prototype, not yet
hardened against malicious local filesystem races or privilege-boundary
attacks. Do not install externally supplied rules from unknown sources.

## Comparing scans

In Results select an analyzed file with a SHA-256 and press
**Compare previous scans**. Virelith reads up to 500 recent local scan
reports from SQLite and compares the latest two snapshots with that exact
hash. It displays changes in verdict, ClamAV/YARA status, YARA matches,
Insight IDs, rule version and scan completeness. A changed detection is
not proof the file is malicious; local history is not tamper-proof and
ClamAV database version isn't yet persisted per scan.

## Kali verification

```bash
cd ~/Projects/Virelith
git fetch origin
git switch feature/v013-evidence-and-yara-management
./.venv/bin/python -m pytest -q
./.venv/bin/python -m virelith.desktop
```

Scan the same benign file twice and compare. For changes use **separately
trusted signed test packages**, never real malware. Verify tampered signature
and unavailable key are rejected. No changes are merged to main automatically.

## Release gates

- Offscreen Qt smoke test and manual GUI validation.
- Signed bundle trust-root UX and failed activation behavior.
- Robustness to malformed stored JSON and unexpected file metadata.
- Real Windows 11 test (path dialogs, permissions, sqlite, signed store).
- Existing SQLite history is not cryptographically authenticated.
