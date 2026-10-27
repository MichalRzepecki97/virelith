# Virelith v0.4 – Update Manager (phase 1)

This release adds **read-only** ClamAV database status checks and **offline**
SHA-256-verified staging of YARA rules.

## Important security boundary

A SHA-256 digest inside a manifest downloaded from the same untrusted source
is **not authentication**. An attacker could change both files. Only accept
a manifest from an independently trusted channel. Do not automatically
activate staged files.

No remote YARA downloads, scheduled installation, publisher signature checking,
atomic activation, or rollback are implemented in this phase. Those capabilities
require a signed-update protocol (e.g. Ed25519 or TUF), pinned trust roots,
version monotonicity and regression tests.

FreshClam is responsible for ClamAV signature updates; the status inspection
never invokes FreshClam or changes its configuration.

## Example: inspect local ClamAV state

```python
from pathlib import Path
from virelith.update_manager import clamav_status
print(clamav_status(database_dir=Path("/var/lib/clamav")))
```

## Example: stage locally trusted YARA rules

```python
from pathlib import Path
from virelith.update_manager import stage_yara_rules
result = stage_yara_rules(
    Path("rules/test_rule.yar"),
    Path("trusted-manifest.json"),
    Path("local-rule-staging"),
)
print(result)
```

The manifest format is:

```json
{"version":"0.4.0","sha256":"<64 lowercase hex characters>"}
```

Run `python -m pytest -q` before merging.
