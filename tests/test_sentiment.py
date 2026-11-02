"""Tests for orbit_ir.sentiment module."""
import json
from pathlib import Path

from orbit_ir.sentiment import analyze_sentiment, format_sentiment_text


def _write_events(path: Path, events: list[dict]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    f = path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def test_sentiment_positive(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "success", "status": "completed"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = analyze_sentiment(inp)
    assert result["tone_distribution"].get("positive", 0) == 1


def test_sentiment_negative(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "error", "status": "failed"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = analyze_sentiment(inp)
    assert result["tone_distribution"].get("negative", 0) == 1


def test_sentiment_neutral(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "tool_call"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = analyze_sentiment(inp)
    assert result["tone_distribution"].get("neutral", 0) == 1


def test_sentiment_mixed(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "success"},
        {"event_id": "e2", "agent_id": "a1", "type": "error"},
        {"event_id": "e3", "agent_id": "a1", "type": "tool_call"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = analyze_sentiment(inp)
    assert result["total_events"] == 3
    assert len(result["tone_distribution"]) >= 2


def test_sentiment_intents(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "query", "action": "search for data"},
        {"event_id": "e2", "agent_id": "a1", "type": "mutate", "action": "create new file"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = analyze_sentiment(inp)
    assert "query" in result["intent_distribution"]
    assert "mutate" in result["intent_distribution"]


def test_sentiment_per_agent(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "success"},
        {"event_id": "e2", "agent_id": "a2", "type": "error"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = analyze_sentiment(inp)
    assert "a1" in result["agent_tones"]
    assert "a2" in result["agent_tones"]


def test_sentiment_empty(tmp_path):
    inp = _write_events(tmp_path / "input", [])
    result = analyze_sentiment(inp)
    assert result["total_events"] == 0


def test_sentiment_annotations(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "error"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = analyze_sentiment(inp)
    assert len(result["annotations"]) == 1
    assert result["annotations"][0]["tone"] == "negative"


def test_format_sentiment_text(tmp_path):
    events = [
        {"event_id": "e1", "agent_id": "a1", "type": "error"},
        {"event_id": "e2", "agent_id": "a1", "type": "success"},
    ]
    inp = _write_events(tmp_path / "input", events)
    result = analyze_sentiment(inp)
    text = format_sentiment_text(result)
    assert "Sentiment Analysis" in text
    assert "positive" in text
    assert "negative" in text
