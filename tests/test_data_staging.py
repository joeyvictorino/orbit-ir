from orbit_ir.data_staging import (
    analyze_staging,
    format_text,
    format_json,
    _load_events,
    _is_temp_path,
    _is_archive_tool,
    _is_write_tool,
    _is_read_tool,
    _is_database_dump,
    _is_disguised,
)


def test_empty_events():
    r = analyze_staging([])
    assert r.summary.total_detections == 0
    assert r.summary.agents_involved == 0


def test_no_staging():
    events = [
        {"agent_id": "a1", "tool": "read_file", "timestamp": "2026-01-01T00:00:00Z"},
    ]
    r = analyze_staging(events)
    assert r.summary.total_detections == 0


def test_local_collection():
    events = [
        {"agent_id": "a1", "tool": "read_file", "timestamp": "2026-01-01T00:00:00Z", "resource": "file1.txt"},
        {"agent_id": "a1", "tool": "read_file", "timestamp": "2026-01-01T00:01:00Z", "resource": "file2.txt"},
        {"agent_id": "a1", "tool": "read_file", "timestamp": "2026-01-01T00:02:00Z", "resource": "file3.txt"},
        {"agent_id": "a1", "tool": "write_file", "timestamp": "2026-01-01T00:03:00Z", "resource": "collected.dat"},
    ]
    r = analyze_staging(events)
    found = [d for d in r.detections if d.technique == "local-collection"]
    assert len(found) == 1
    assert found[0].staged_location == "collected.dat"
    assert len(found[0].data_sources) == 3


def test_temp_staging():
    events = [
        {"agent_id": "a1", "tool": "write_file", "timestamp": "2026-01-01T00:00:00Z",
         "resource": "/tmp/staged_data.bin"},
    ]
    r = analyze_staging(events)
    found = [d for d in r.detections if d.technique == "temp-staging"]
    assert len(found) == 1
    assert found[0].staged_location == "/tmp/staged_data.bin"


def test_archive_creation():
    events = [
        {"agent_id": "a1", "tool": "read_file", "timestamp": "2026-01-01T00:00:00Z", "resource": "a.txt"},
        {"agent_id": "a1", "tool": "read_file", "timestamp": "2026-01-01T00:01:00Z", "resource": "b.txt"},
        {"agent_id": "a1", "tool": "read_file", "timestamp": "2026-01-01T00:02:00Z", "resource": "c.txt"},
        {"agent_id": "a1", "tool": "tar", "timestamp": "2026-01-01T00:03:00Z", "resource": "backup.tar.gz"},
    ]
    r = analyze_staging(events)
    found = [d for d in r.detections if d.technique == "archive-creation"]
    assert len(found) == 1
    assert found[0].confidence == "high"


def test_rename_disguise():
    events = [
        {"agent_id": "a1", "tool": "rename_file", "timestamp": "2026-01-01T00:00:00Z",
         "resource": "secret_data.log", "source": "exfil_payload.zip"},
    ]
    r = analyze_staging(events)
    found = [d for d in r.detections if d.technique == "rename-disguise"]
    assert len(found) == 1
    assert found[0].staged_location == "secret_data.log"


def test_chunked_staging():
    events = [
        {"agent_id": "a1", "tool": "write_file", "timestamp": f"2026-01-01T00:0{i}:00Z",
         "resource": f"chunk_{i}.bin"}
        for i in range(5)
    ]
    r = analyze_staging(events)
    found = [d for d in r.detections if d.technique == "chunked-staging"]
    assert len(found) >= 1


def test_database_dump():
    events = [
        {"agent_id": "a1", "tool": "pg_dump", "timestamp": "2026-01-01T00:00:00Z",
         "resource": "users_table.sql"},
    ]
    r = analyze_staging(events)
    found = [d for d in r.detections if d.technique == "database-dump"]
    assert len(found) == 1
    assert found[0].confidence == "high"


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "write_file", "timestamp": "2026-01-01T00:00:00Z",
         "resource": "/tmp/data1.bin"},
        {"agent_id": "a2", "tool": "pg_dump", "timestamp": "2026-01-01T00:00:00Z",
         "resource": "dump.sql"},
    ]
    r = analyze_staging(events)
    assert r.summary.agents_involved == 2


def test_is_temp_path():
    assert _is_temp_path("/tmp/data.bin")
    assert _is_temp_path("/var/tmp/staging")
    assert _is_temp_path("/dev/shm/buffer")
    assert _is_temp_path("file.tmp")
    assert not _is_temp_path("/home/user/data.txt")


def test_is_archive_tool():
    assert _is_archive_tool("tar")
    assert _is_archive_tool("zip")
    assert _is_archive_tool("create_archive")
    assert not _is_archive_tool("read_file")


def test_is_write_tool():
    assert _is_write_tool("write_file")
    assert _is_write_tool("create_file")
    assert not _is_write_tool("read_file")


def test_is_read_tool():
    assert _is_read_tool("read_file")
    assert _is_read_tool("query_db")
    assert not _is_read_tool("write_file")


def test_is_database_dump():
    assert _is_database_dump("pg_dump")
    assert _is_database_dump("mysqldump")
    assert _is_database_dump("dump_table")
    assert not _is_database_dump("read_file")


def test_is_disguised():
    assert _is_disguised("data.log")
    assert _is_disguised("config.bak")
    assert _is_disguised("temp.dat")
    assert not _is_disguised("data.zip")


def test_bytes_estimate():
    events = [
        {"agent_id": "a1", "tool": "write_file", "timestamp": "2026-01-01T00:00:00Z",
         "resource": "/tmp/data.bin", "bytes": 5000},
    ]
    r = analyze_staging(events)
    found = [d for d in r.detections if d.technique == "temp-staging"]
    assert len(found) == 1
    assert found[0].bytes_estimate == 5000


def test_summary_temp_locations():
    events = [
        {"agent_id": "a1", "tool": "write_file", "timestamp": "2026-01-01T00:00:00Z",
         "resource": "/tmp/file1.bin"},
        {"agent_id": "a1", "tool": "write_file", "timestamp": "2026-01-01T00:01:00Z",
         "resource": "/var/tmp/file2.bin"},
    ]
    r = analyze_staging(events)
    assert r.summary.temp_locations_used >= 2


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "pg_dump", "timestamp": "2026-01-01T00:00:00Z",
         "resource": "dump.sql"},
    ]
    r = analyze_staging(events)
    text = format_text(r)
    assert "Data Staging Detection Report" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "pg_dump", "timestamp": "2026-01-01T00:00:00Z",
         "resource": "dump.sql"},
    ]
    r = analyze_staging(events)
    j = format_json(r)
    assert '"detections"' in j
    assert '"summary"' in j


def test_skip_empty_agent():
    events = [
        {"agent_id": "", "tool": "pg_dump", "timestamp": "2026-01-01T00:00:00Z"},
    ]
    r = analyze_staging(events)
    assert r.summary.total_detections == 0


def test_timeline_ordering():
    events = [
        {"agent_id": "a1", "tool": "write_file", "timestamp": "2026-01-01T00:02:00Z",
         "resource": "/tmp/b.bin"},
        {"agent_id": "a1", "tool": "pg_dump", "timestamp": "2026-01-01T00:01:00Z",
         "resource": "dump.sql"},
    ]
    r = analyze_staging(events)
    if len(r.timeline) >= 2:
        assert r.timeline[0]["timestamp"] <= r.timeline[1]["timestamp"]
