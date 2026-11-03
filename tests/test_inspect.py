import json
from pathlib import Path

import pytest
from orbit_ir.inspect import inspect_event, format_inspect_text, list_events, _nested_depth


def _write_events(path: Path, events: list[dict]) -> Path:
    f = path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return f


def test_inspect_by_index(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "2026-01-01T00:00:00Z", "event_type": "tool_call"},
        {"event_id": "e2", "agent_id": "a2", "timestamp": "2026-01-01T00:01:00Z", "event_type": "response"},
        {"event_id": "e3", "agent_id": "a1", "timestamp": "2026-01-01T00:02:00Z", "event_type": "tool_call"},
    ]
    f = _write_events(tmp_path, events)
    result = inspect_event(f, index=1)
    assert result["index"] == 1
    assert result["total_events"] == 3
    assert result["event"]["event_id"] == "e2"
    assert len(result["context_before"]) == 1
    assert len(result["context_after"]) == 1


def test_inspect_by_event_id(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "T1"},
        {"event_id": "e2", "agent_id": "a2", "timestamp": "T2"},
        {"event_id": "e3", "agent_id": "a3", "timestamp": "T3"},
    ]
    f = _write_events(tmp_path, events)
    result = inspect_event(f, event_id="e3")
    assert result["index"] == 2
    assert result["event"]["event_id"] == "e3"


def test_inspect_context_bounds(tmp_path):
    events = [{"event_id": f"e{i}", "timestamp": f"T{i}"} for i in range(10)]
    f = _write_events(tmp_path, events)
    result = inspect_event(f, index=0, context=3)
    assert len(result["context_before"]) == 0
    assert len(result["context_after"]) == 3

    result = inspect_event(f, index=9, context=3)
    assert len(result["context_before"]) == 3
    assert len(result["context_after"]) == 0


def test_inspect_bad_index(tmp_path):
    events = [{"event_id": "e1"}]
    f = _write_events(tmp_path, events)
    with pytest.raises(ValueError, match="out of range"):
        inspect_event(f, index=5)


def test_inspect_missing_event_id(tmp_path):
    events = [{"event_id": "e1"}]
    f = _write_events(tmp_path, events)
    with pytest.raises(ValueError, match="not found"):
        inspect_event(f, event_id="nonexistent")


def test_inspect_directory(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "T1"},
        {"event_id": "e2", "agent_id": "a2", "timestamp": "T2"},
    ]
    _write_events(tmp_path, events)
    result = inspect_event(tmp_path, index=0)
    assert result["total_events"] == 2


def test_format_inspect_text(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "timestamp": "T1", "event_type": "tool_call"},
        {"event_id": "e2", "agent_id": "a2", "timestamp": "T2", "event_type": "response"},
    ]
    f = _write_events(tmp_path, events)
    result = inspect_event(f, index=0, context=1)
    text = format_inspect_text(result)
    assert "Event #0" in text
    assert "a1" in text
    assert "tool_call" in text


def test_inspect_no_args(tmp_path):
    events = [{"event_id": "e1"}]
    f = _write_events(tmp_path, events)
    with pytest.raises(ValueError, match="either"):
        inspect_event(f)


def test_inspect_empty(tmp_path):
    f = tmp_path / "empty.jsonl"
    f.write_text("")
    with pytest.raises(ValueError, match="no events"):
        inspect_event(f, index=0)


def test_list_events(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "message"},
        {"event_id": "e2", "agent_id": "a2", "type": "tool_call"},
    ]
    _write_events(tmp_path, events)
    result = list_events(tmp_path)
    assert result["total_events"] == 2
    assert len(result["index"]) == 2
    assert result["index"][0].get("event_id") == "e1"


def test_list_events_format(tmp_path):
    events = [{"event_id": "e1", "agent_id": "a1", "type": "message"}]
    _write_events(tmp_path, events)
    result = list_events(tmp_path)
    text = format_inspect_text(result)
    assert "Events:" in text
    assert "e1" in text


def test_nested_depth():
    assert _nested_depth("hello") == 0
    assert _nested_depth({"a": 1}) == 1
    assert _nested_depth({"a": {"b": 1}}) == 2
    assert _nested_depth({"a": [{"b": 1}]}) == 3
