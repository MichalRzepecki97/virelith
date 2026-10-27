# Signed update prototype v0.5

This prototype verifies an **offline** Ed25519 signature over the exact manifest
bytes, checks the rules SHA-256, compiles with YARA-X, then switches current.json
with an atomic rename. No network fetching or scheduler is implemented.

## Trust model and limitations

The 32-byte raw public key must be provisioned independently and pinned.
Never accept a key supplied alongside an untrusted update bundle.

The store must be a trusted, access-controlled local directory. This initial
implementation does **not** protect against a local attacker able to change
current.json, signed rule files, or the trusted key. It does not implement
cross-process locking, crash recovery for orphaned rule files, key rotation,
offline root metadata, signature expiry, or durable anti-rollback after an
operator-triggered rollback. Do not enable unattended updates yet.

Rollback is manual and only supported for the immediate previous local version,
when the scanner is stopped. Test on disposable data only.

## Usage from Python

```python
from pathlib import Path
from virelith.signed_updates import activate_signed_rules, rollback_rules

result = activate_signed_rules(
    Path("bundle/rules.yar"),
    Path("bundle/manifest.json"),
    Path("bundle/manifest.sig"),
    Path("trusted/publisher.pub"),
    Path("state/rules"),
)
print(result)
```

Manifest schema: `{"version":"1.0.0","sha256":"<lowercase SHA-256>"}`.
Signature: 64 raw bytes of Ed25519 over exact UTF-8 manifest contents.
Public key: 32 raw Ed25519 bytes.

This does not yet integrate with CLI --rules or download updates; active rules
are staged state for subsequent scanner integration.
