"""Tests for the search module."""

import json
from pathlib import Path

from orbit_ir.search import search_evidence, format_search_text


def _write_evidence(tmp_path: Path) -> Path:
    events = [
        {"timestamp": "2025-01-01T10:00:00Z", "agent": "recon-agent", "action": "http_get", "detail": "Fetched /api/users"},
        {"timestamp": "2025-01-01T11:00:00Z", "agent": "exploit-agent", "action": "sql_inject", "detail": "SQL injection on login"},
        {"timestamp": "2025-01-01T12:00:00Z", "agent": "recon-agent", "action": "dns_lookup", "detail": "Resolved internal host"},
        {"timestamp": "2025-01-01T13:00:00Z", "agent": "exfil-agent", "action": "http_post", "detail": "Uploaded data to external"},
    ]
    p = tmp_path / "evidence.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return p


def test_search_all(tmp_path):
    p = _write_evidence(tmp_path)
    results = search_evidence(p)
    assert len(results) == 4


def test_search_by_agent(tmp_path):
    p = _write_evidence(tmp_path)
    results = search_evidence(p, agent="recon-agent")
    assert len(results) == 2
    assert all(r["agent"] == "recon-agent" for r in results)


def test_search_by_action(tmp_path):
    p = _write_evidence(tmp_path)
    results = search_evidence(p, action="sql_inject")
    assert len(results) == 1
    assert results[0]["agent"] == "exploit-agent"


def test_search_by_query(tmp_path):
    p = _write_evidence(tmp_path)
    results = search_evidence(p, query="sql")
    assert len(results) == 1


def test_search_by_time_range(tmp_path):
    p = _write_evidence(tmp_path)
    results = search_evidence(p, after="2025-01-01T10:30:00Z", before="2025-01-01T12:30:00Z")
    assert len(results) == 2


def test_search_combined_filters(tmp_path):
    p = _write_evidence(tmp_path)
    results = search_evidence(p, agent="recon-agent", after="2025-01-01T11:00:00Z")
    assert len(results) == 1
    assert results[0]["action"] == "dns_lookup"


def test_search_no_match(tmp_path):
    p = _write_evidence(tmp_path)
    results = search_evidence(p, agent="nonexistent")
    assert len(results) == 0


def test_format_search_text_empty():
    text = format_search_text([])
    assert "No matching" in text


def test_format_search_text():
    events = [{"timestamp": "2025-01-01T10:00:00Z", "agent": "a", "action": "b", "detail": "c"}]
    text = format_search_text(events)
    assert "1 matching" in text
    assert "a -> b" in text
