"""Offline GUI YARA activation must retain signature validation."""
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from virelith.yara_bundle_manager import activate_bundle

RULE = b'rule Virelith_Offline_Demo { condition: true }'


def create_bundle(tmp_path):
    private = Ed25519PrivateKey.generate()
    pub = tmp_path / "trusted.pub"
    pub.write_bytes(private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw))
    rules = tmp_path / "rules.yar"
    rules.write_bytes(RULE)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"version": "1.0.0",
                                    "sha256": hashlib.sha256(RULE).hexdigest()}))
    signature = tmp_path / "manifest.sig"
    signature.write_bytes(private.sign(manifest.read_bytes()))
    return rules, manifest, signature, pub


def test_valid_signed_bundle_activates(tmp_path):
    args = create_bundle(tmp_path)
    outcome = activate_bundle(*args, tmp_path / "store")
    assert outcome["status"] == "activated"


def test_untrusted_signature_does_not_activate(tmp_path):
    rules, manifest, signature, trusted = create_bundle(tmp_path)
    signature.write_bytes(b"x" * 64)
    outcome = activate_bundle(rules, manifest, signature, trusted, tmp_path / "store")
    assert outcome["status"] == "error"
    assert not (tmp_path / "store" / "current.json").exists()


def test_missing_trusted_key_rejected(tmp_path):
    rules, manifest, signature, _ = create_bundle(tmp_path)
    result = activate_bundle(rules, manifest, signature,
                             tmp_path / "nonexistent.pub", tmp_path / "store")
    assert result["status"] == "error"
