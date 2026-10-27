from virelith.quarantine import quarantine_file, list_quarantine, restore_file


def test_requires_confirmation(tmp_path):
    source = tmp_path / "safe.txt"
    source.write_text("sample")
    store = tmp_path / "store"
    assert quarantine_file(source, store)["status"] == "confirmation_required"
    assert source.exists()


def test_quarantine_and_restore(tmp_path):
    source = tmp_path / "safe.txt"
    source.write_text("safe data")
    store = tmp_path / "store"
    result = quarantine_file(source, store, confirmed=True)
    assert result["status"] == "quarantined"
    assert not source.exists()
    assert len(list_quarantine(store)) == 1
    restored = restore_file(result["id"], store, confirmed=True)
    assert restored["status"] == "restored"
    assert source.read_text() == "safe data"


def test_restore_never_overwrites(tmp_path):
    source = tmp_path / "test.txt"
    source.write_text("original")
    store = tmp_path / "store"
    result = quarantine_file(source, store, confirmed=True)
    source.write_text("new")
    assert restore_file(result["id"], store, confirmed=True)["status"] == "error"
    assert source.read_text() == "new"


def test_symlink_rejected(tmp_path):
    original = tmp_path / "real.txt"
    original.write_text("safe")
    link = tmp_path / "link.txt"
    link.symlink_to(original)
    result = quarantine_file(link, tmp_path / "store", confirmed=True)
    assert result["status"] == "error"
    assert original.exists()


def test_invalid_id(tmp_path):
    assert restore_file("../escape", tmp_path / "store", confirmed=True)["status"] == "error"
