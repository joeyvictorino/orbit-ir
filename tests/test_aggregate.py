"""Tests for orbit_ir.aggregate module."""
import json
from pathlib import Path

from orbit_ir.aggregate import aggregate_events, format_aggregate_text


def _write_events(path: Path, events: list[dict]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    f = path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def test_aggregate_union_basic(tmp_path):
    events_a = [
        {"event_id": "e1", "agent_id": "a1"},
        {"event_id": "e2", "agent_id": "a1"},
    ]
    events_b = [
        {"event_id": "e3", "agent_id": "a2"},
    ]
    dir_a = _write_events(tmp_path / "a", events_a)
    dir_b = _write_events(tmp_path / "b", events_b)
    result = aggregate_events([dir_a, dir_b], strategy="union")
    assert result["total_input"] == 3
    assert result["total_output"] == 3
    assert len(result["events"]) == 3
    assert result["strategy"] == "union"


def test_aggregate_union_deduplicates(tmp_path):
    events_a = [
        {"event_id": "e1", "agent_id": "a1"},
        {"event_id": "e2", "agent_id": "a1"},
    ]
    events_b = [
        {"event_id": "e1", "agent_id": "a1"},
        {"event_id": "e3", "agent_id": "a2"},
    ]
    dir_a = _write_events(tmp_path / "a", events_a)
    dir_b = _write_events(tmp_path / "b", events_b)
    result = aggregate_events([dir_a, dir_b], strategy="union")
    assert result["total_input"] == 4
    assert result["total_output"] == 3
    ids = {e["event_id"] for e in result["events"]}
    assert ids == {"e1", "e2", "e3"}


def test_aggregate_union_no_dedup(tmp_path):
    events_a = [{"event_id": "e1"}]
    events_b = [{"event_id": "e1"}]
    dir_a = _write_events(tmp_path / "a", events_a)
    dir_b = _write_events(tmp_path / "b", events_b)
    result = aggregate_events([dir_a, dir_b], strategy="union", deduplicate=False)
    assert result["total_output"] == 2


def test_aggregate_intersect(tmp_path):
    events_a = [
        {"event_id": "e1", "agent_id": "a1"},
        {"event_id": "e2", "agent_id": "a1"},
    ]
    events_b = [
        {"event_id": "e1", "agent_id": "a1"},
        {"event_id": "e3", "agent_id": "a2"},
    ]
    dir_a = _write_events(tmp_path / "a", events_a)
    dir_b = _write_events(tmp_path / "b", events_b)
    result = aggregate_events([dir_a, dir_b], strategy="intersect")
    assert result["total_output"] == 1
    assert result["events"][0]["event_id"] == "e1"


def test_aggregate_unique(tmp_path):
    events_a = [
        {"event_id": "e1"},
        {"event_id": "e2"},
    ]
    events_b = [
        {"event_id": "e1"},
        {"event_id": "e3"},
    ]
    dir_a = _write_events(tmp_path / "a", events_a)
    dir_b = _write_events(tmp_path / "b", events_b)
    result = aggregate_events([dir_a, dir_b], strategy="unique")
    assert result["total_output"] == 2
    ids = {e["event_id"] for e in result["events"]}
    assert ids == {"e2", "e3"}


def test_aggregate_source_stats(tmp_path):
    events_a = [{"event_id": "e1"}, {"event_id": "e2"}]
    events_b = [{"event_id": "e3"}]
    dir_a = _write_events(tmp_path / "a", events_a)
    dir_b = _write_events(tmp_path / "b", events_b)
    result = aggregate_events([dir_a, dir_b])
    assert len(result["sources"]) == 2
    assert result["sources"][0]["event_count"] == 2
    assert result["sources"][1]["event_count"] == 1


def test_aggregate_from_files(tmp_path):
    f1 = tmp_path / "a.jsonl"
    f2 = tmp_path / "b.jsonl"
    f1.write_text(json.dumps({"event_id": "e1"}) + "\n")
    f2.write_text(json.dumps({"event_id": "e2"}) + "\n")
    result = aggregate_events([f1, f2])
    assert result["total_output"] == 2


def test_aggregate_empty(tmp_path):
    dir_a = _write_events(tmp_path / "a", [])
    result = aggregate_events([dir_a])
    assert result["total_output"] == 0
    assert result["events"] == []


def test_format_aggregate_text(tmp_path):
    events_a = [{"event_id": "e1"}, {"event_id": "e2"}]
    events_b = [{"event_id": "e1"}]
    dir_a = _write_events(tmp_path / "a", events_a)
    dir_b = _write_events(tmp_path / "b", events_b)
    result = aggregate_events([dir_a, dir_b])
    text = format_aggregate_text(result)
    assert "Aggregate:" in text
    assert "Sources: 2" in text
    assert "Output events: 2" in text
    assert "Duplicates removed: 1" in text
