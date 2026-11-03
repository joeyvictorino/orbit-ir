"""Tests for orbit_ir.filter module (complex event queries)."""
import json
from pathlib import Path

import pytest
from orbit_ir.filter import (
    FilterExpr,
    parse_expr,
    parse_query,
    event_matches,
    filter_events,
    format_filter_text,
)


def _write_events(path: Path, events: list[dict]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    f = path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def test_parse_expr_equal():
    e = parse_expr("agent_id=a1")
    assert e.field == "agent_id"
    assert e.op == "="
    assert e.value == "a1"


def test_parse_expr_not_equal():
    e = parse_expr("type!=tool_call")
    assert e.op == "!="
    assert e.value == "tool_call"


def test_parse_expr_regex():
    e = parse_expr("message~error.*timeout")
    assert e.op == "~"
    assert e.value == "error.*timeout"


def test_parse_expr_greater():
    e = parse_expr("score>0.5")
    assert e.op == ">"
    assert e.value == "0.5"


def test_parse_expr_invalid():
    with pytest.raises(ValueError, match="invalid"):
        parse_expr("no-operator-here")


def test_parse_query_and():
    clauses = parse_query("agent_id=a1,type=tool_call")
    assert len(clauses) == 1
    assert len(clauses[0]) == 2


def test_parse_query_or():
    clauses = parse_query("agent_id=a1|agent_id=a2")
    assert len(clauses) == 2
    assert len(clauses[0]) == 1
    assert len(clauses[1]) == 1


def test_parse_query_mixed():
    clauses = parse_query("agent_id=a1,type=tool_call|agent_id=a2")
    assert len(clauses) == 2
    assert len(clauses[0]) == 2
    assert len(clauses[1]) == 1


def test_event_matches_equal():
    ev = {"agent_id": "a1", "type": "tool_call"}
    clauses = parse_query("agent_id=a1")
    assert event_matches(ev, clauses)


def test_event_matches_not_equal():
    ev = {"agent_id": "a1", "type": "tool_call"}
    clauses = parse_query("agent_id!=a2")
    assert event_matches(ev, clauses)


def test_event_matches_regex():
    ev = {"message": "error: connection timeout at 10:30"}
    clauses = parse_query("message~timeout")
    assert event_matches(ev, clauses)


def test_event_matches_greater():
    ev = {"score": 0.8}
    clauses = parse_query("score>0.5")
    assert event_matches(ev, clauses)


def test_event_matches_and_both_required():
    ev = {"agent_id": "a1", "type": "response"}
    clauses = parse_query("agent_id=a1,type=tool_call")
    assert not event_matches(ev, clauses)


def test_event_matches_or_either_sufficient():
    ev = {"agent_id": "a2", "type": "response"}
    clauses = parse_query("agent_id=a1|agent_id=a2")
    assert event_matches(ev, clauses)


def test_event_matches_nested_field():
    ev = {"data": {"source": "api"}}
    clauses = parse_query("data.source=api")
    assert event_matches(ev, clauses)


def test_event_matches_missing_field():
    ev = {"agent_id": "a1"}
    clauses = parse_query("type=tool_call")
    assert not event_matches(ev, clauses)


def test_filter_events(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "tool_call"},
        {"event_id": "e2", "agent_id": "a2", "type": "response"},
        {"event_id": "e3", "agent_id": "a1", "type": "response"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = filter_events(inp, "agent_id=a1")
    assert result["total_events"] == 3
    assert result["matched"] == 2
    assert len(result["events"]) == 2
    assert result["events"][0]["event_id"] == "e1"
    assert result["events"][1]["event_id"] == "e3"


def test_filter_events_limit(tmp_path):
    events = [
        {"event_id": f"e{i}", "agent_id": "a1"} for i in range(10)
    ]
    inp = _write_events(tmp_path / "input", events)
    result = filter_events(inp, "agent_id=a1", limit=3)
    assert result["matched"] == 3
    assert len(result["events"]) == 3


def test_filter_events_no_match(tmp_path):
    events = [{"event_id": "e1", "agent_id": "a1"}]
    inp = _write_events(tmp_path / "input", events)
    result = filter_events(inp, "agent_id=a99")
    assert result["matched"] == 0


def test_filter_events_file(tmp_path):
    events = [
        {"event_id": "e1", "type": "tool_call"},
        {"event_id": "e2", "type": "response"},
    ]
    f = tmp_path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    result = filter_events(f, "type=tool_call")
    assert result["matched"] == 1


def test_format_filter_text(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "tool_call", "timestamp": "T1"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = filter_events(inp, "agent_id=a1")
    text = format_filter_text(result)
    assert "Matched 1" in text
    assert "e1" in text
    assert "a1" in text


def test_filter_less_than(tmp_path):
    events = [
        {"event_id": "e1", "score": 0.3},
        {"event_id": "e2", "score": 0.7},
        {"event_id": "e3", "score": 0.5},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = filter_events(inp, "score<0.5")
    assert result["matched"] == 1
    assert result["events"][0]["event_id"] == "e1"


def test_filter_gte(tmp_path):
    events = [
        {"event_id": "e1", "score": 0.5},
        {"event_id": "e2", "score": 0.3},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = filter_events(inp, "score>=0.5")
    assert result["matched"] == 1
    assert result["events"][0]["event_id"] == "e1"
