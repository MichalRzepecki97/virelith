from virelith.history_filters import filter_scans

RECORDS = [
    {"target": "/tmp/Hello.EXE", "detections": 0},
    {"target": "/tmp/suspicious.exe", "detections": 2},
    {"target": "/tmp/note.txt", "detections": 0},
]

def test_case_insensitive_query():
    assert [x["target"] for x in filter_scans(RECORDS, "hello")] == ["/tmp/Hello.EXE"]

def test_detection_filter():
    assert len(filter_scans(RECORDS, verdict="detections")) == 1
    assert len(filter_scans(RECORDS, verdict="no_detections")) == 2

def test_combined_filter():
    assert filter_scans(RECORDS, "hello", "detections") == []
