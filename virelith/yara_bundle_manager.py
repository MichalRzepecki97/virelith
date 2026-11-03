"""Explicit, trusted-key YARA package activation in GUI.

No keys downloaded or accepted from the package as authority. Operator must
configure an independently provisioned Ed25519 public key before activation.
"""
from __future__ import annotations

from pathlib import Path
from .signed_updates import activate_signed_rules
from .active_rules import load_active_rules


def activate_bundle(rules: Path, manifest: Path, signature: Path,
                    trusted_key: Path, store: Path) -> dict:
    """Validate configured trust inputs, then use existing signed update verifier."""
    for path in (rules, manifest, signature, trusted_key):
        if not path.is_file() or path.is_symlink():
            return {"status": "error", "detail": f"Missing or unsafe input: {path.name}"}
    if not trusted_key.is_absolute() or store.is_symlink():
        return {"status": "error", "detail": "Trusted key must use absolute path; symlink stores are not allowed"}
    result = activate_signed_rules(rules, manifest, signature, trusted_key, store)
    if result.get("status") != "activated":
        return result
    try:
        _, metadata = load_active_rules(store)
        if metadata["version"] != result["version"]:
            raise ValueError("activated version differs from verified store")
    except (OSError, ValueError, KeyError) as exc:
        return {"status": "error", "detail": "Activated store validation failed: " + str(exc)[:200]}
    return result
