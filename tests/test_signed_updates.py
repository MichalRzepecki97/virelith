import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from virelith.signed_updates import activate_signed_rules, rollback_rules


RULE = b'rule Signed_Test { strings: $a = "VIRELITH_SIGNED_TEST" condition: $a }'


def bundle(tmp_path, version="1.0.0"):
    private = Ed25519PrivateKey.generate()
    key = tmp_path / "key.pub"
    key.write_bytes(private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw))
    rules = tmp_path / "rules.yar"
    rules.write_bytes(RULE)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"version": version,
                                    "sha256": hashlib.sha256(RULE).hexdigest()}))
    signature = tmp_path / "manifest.sig"
    signature.write_bytes(private.sign(manifest.read_bytes()))
    return rules, manifest, signature, key, private


def test_signed_activation(tmp_path):
    args = bundle(tmp_path)
    result = activate_signed_rules(*args[:4], tmp_path / "store")
    assert result["status"] == "activated"
    assert json.loads((tmp_path / "store/current.json").read_text())["version"] == "1.0.0"


def test_tampered_manifest_rejected(tmp_path):
    rules, manifest, signature, key, _ = bundle(tmp_path)
    manifest.write_text(manifest.read_text().replace("1.0.0", "2.0.0"))
    assert activate_signed_rules(rules, manifest, signature, key, tmp_path / "store")["status"] == "error"


def test_tampered_rules_rejected(tmp_path):
    rules, manifest, signature, key, _ = bundle(tmp_path)
    rules.write_bytes(RULE + b" changed")
    assert activate_signed_rules(rules, manifest, signature, key, tmp_path / "store")["status"] == "error"


def test_replay_rejected(tmp_path):
    args = bundle(tmp_path)
    store = tmp_path / "store"
    assert activate_signed_rules(*args[:4], store)["status"] == "activated"
    assert activate_signed_rules(*args[:4], store)["status"] == "error"


def test_bad_public_key_rejected(tmp_path):
    rules, manifest, signature, key, _ = bundle(tmp_path)
    key.write_bytes(b"x" * 32)
    assert activate_signed_rules(rules, manifest, signature, key, tmp_path / "store")["status"] == "error"


def test_no_previous_rollback(tmp_path):
    args = bundle(tmp_path)
    store = tmp_path / "store"
    activate_signed_rules(*args[:4], store)
    assert rollback_rules(store)["status"] == "error"
