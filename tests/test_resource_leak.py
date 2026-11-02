"""Tests for resource leak detection."""
from orbit_ir.resource_leak import (
    analyze_resource_leaks,
    format_text,
    format_json,
    _classify_event,
    _detect_unreleased,
)


def test_empty_events():
    r = analyze_resource_leaks([])
    assert r.total_events == 0
    assert r.leak_events == 0
    assert r.risk_level == "none"


def test_no_leaks():
    events = [
        {"agent_id": "a1", "message": "normal processing", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_resource_leaks(events)
    assert r.leak_events == 0
    assert r.risk_level == "none"


def test_file_handle_leak():
    events = [
        {"agent_id": "a1", "message": "file handle leak detected for /tmp/data.txt", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_leaks(events)
    assert r.leak_events == 1
    assert any(cs.category == "file_handle_leak" and cs.count > 0 for cs in r.categories)


def test_connection_leak():
    events = [
        {"agent_id": "a1", "message": "connection leak: socket not closed to db:5432", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_leaks(events)
    assert r.leak_events == 1
    assert any(cs.category == "connection_leak" and cs.count > 0 for cs in r.categories)


def test_lock_leak():
    events = [
        {"agent_id": "a1", "message": "mutex leak detected, lock not released after timeout", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_leaks(events)
    assert r.leak_events == 1
    assert any(cs.category == "lock_leak" and cs.count > 0 for cs in r.categories)


def test_memory_leak():
    events = [
        {"agent_id": "a1", "message": "memory leak: heap growth unbounded, OOM imminent", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_leaks(events)
    assert r.leak_events == 1
    assert any(cs.category == "memory_leak" and cs.count > 0 for cs in r.categories)


def test_resource_exhaustion():
    events = [
        {"agent_id": "a1", "message": "resource exhaustion: intentional fork bomb detected", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_leaks(events)
    assert r.leak_events == 1
    assert any(cs.category == "resource_exhaustion" and cs.count > 0 for cs in r.categories)


def test_acquire_without_release():
    events = [
        {"agent_id": "a1", "message": "resource token leak: permit not released after operation", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_leaks(events)
    assert r.leak_events == 1
    assert any(cs.category == "acquire_without_release" and cs.count > 0 for cs in r.categories)


def test_multiple_leak_types():
    events = [
        {"agent_id": "a1", "message": "file handle leak for /tmp/data", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "connection pool empty, socket leak", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a2", "message": "deadlock detected, mutex not released", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_resource_leaks(events)
    assert r.leak_events == 3
    assert r.risk_score > 0


def test_unreleased_detection():
    events = [
        {"agent_id": "a1", "message": "open file /tmp/data.txt", "resource": "file", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "processing data", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    unreleased = _detect_unreleased(events)
    assert len(unreleased) >= 1
    assert unreleased[0].leaked is True


def test_released_not_flagged():
    events = [
        {"agent_id": "a1", "message": "open file /tmp/data.txt", "resource": "file", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "close file /tmp/data.txt", "resource": "file", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    unreleased = _detect_unreleased(events)
    leaked = [u for u in unreleased if u.leaked]
    assert len(leaked) == 0


def test_risk_levels():
    events = [
        {"agent_id": "a1", "message": "resource exhaustion: deliberate allocation storm", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_leaks(events)
    assert r.risk_level in ("critical", "high", "medium")
    assert r.risk_score > 0


def test_resource_types_seen():
    events = [
        {"agent_id": "a1", "message": "file handle leak in processing", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "socket connection leak detected", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_resource_leaks(events)
    assert len(r.resource_types_seen) >= 1


def test_format_text_output():
    events = [
        {"agent_id": "a1", "message": "memory leak: heap not freed, OOM", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_leaks(events)
    text = format_text(r)
    assert "Resource Leak" in text
    assert "memory_leak" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "message": "file handle leak detected", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_resource_leaks(events)
    import json
    data = json.loads(format_json(r))
    assert "categories" in data
    assert "risk_score" in data
    assert data["total_events"] == 1
