import hashlib
import json
import pytest
from virelith.active_rules import load_active_rules


RULES = 'rule Local_Test { condition: true }'


def make_store(tmp_path):
    digest = hashlib.sha256(RULES.encode()).hexdigest()
    file = tmp_path / f"rules-1.0.0-{digest[:16]}.yar"
    file.write_text(RULES)
    (tmp_path / "current.json").write_text(json.dumps({
        "version": "1.0.0", "file": file.name, "sha256": digest
    }))
    return file


def test_valid_store(tmp_path):
    make_store(tmp_path)
    contents, info = load_active_rules(tmp_path)
    assert contents == RULES
    assert info["version"] == "1.0.0"


def test_tampering_fails(tmp_path):
    file = make_store(tmp_path)
    file.write_text("modified")
    with pytest.raises(ValueError, match="checksum"):
        load_active_rules(tmp_path)


def test_missing_store_fails(tmp_path):
    with pytest.raises(ValueError, match="cannot load"):
        load_active_rules(tmp_path)


def test_traversal_fails(tmp_path):
    make_store(tmp_path)
    state = json.loads((tmp_path / "current.json").read_text())
    state["file"] = "../outside.yar"
    (tmp_path / "current.json").write_text(json.dumps(state))
    with pytest.raises(ValueError, match="filename"):
        load_active_rules(tmp_path)


def test_symlink_fails(tmp_path):
    file = make_store(tmp_path)
    link = tmp_path / "link.yar"
    link.symlink_to(file)
    state = json.loads((tmp_path / "current.json").read_text())
    file.unlink()
    link.rename(file)
    with pytest.raises(ValueError, match="symlink"):
        load_active_rules(tmp_path)
