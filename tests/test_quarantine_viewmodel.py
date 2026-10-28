from virelith.quarantine_viewmodel import summarize_quarantine, filter_quarantine, quarantine_row

DATA = [
    {"id":"one", "original":"/tmp/Hello.EXE", "state":"quarantined", "created_utc":"2026-10-28"},
    {"id":"two", "original":"/tmp/test.txt", "state":"restored", "created_utc":"2026-10-27"},
]

def test_summary_from_records():
    assert summarize_quarantine(DATA) == {"total":2, "quarantined":1, "restored":1}

def test_query_and_state():
    assert len(filter_quarantine(DATA, "hello", "quarantined")) == 1
    assert filter_quarantine(DATA, "hello", "restored") == []

def test_display_name():
    assert quarantine_row(DATA[0])[0] == "Hello.EXE"
