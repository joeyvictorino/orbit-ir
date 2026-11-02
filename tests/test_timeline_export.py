"""Tests for orbit_ir.timeline_export."""

import json
import tempfile
from pathlib import Path

import pytest

from orbit_ir.timeline_export import TimelineExporter, export_timeline, _format_ics_dt


@pytest.fixture
def evidence_dir(tmp_path):
    events = [
        {"timestamp": "2024-01-15T10:00:00Z", "agent_id": "agent-1", "action": "read", "target": "db-1", "severity": "low", "details": "Read database"},
        {"timestamp": "2024-01-15T10:05:00Z", "agent_id": "agent-2", "action": "execute", "target": "cmd-1", "severity": "high", "details": "Executed command"},
        {"timestamp": "2024-01-15T10:10:00Z", "agent_id": "agent-1", "action": "write", "target": "file-1", "severity": "medium", "details": "Wrote file"},
        {"timestamp": "2024-01-15T09:55:00Z", "agent_id": "agent-3", "action": "login", "target": "system-1", "severity": "info", "details": "Logged in"},
    ]
    f = tmp_path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events))
    return tmp_path


def test_csv_export(evidence_dir):
    exporter = TimelineExporter()
    exporter.load(evidence_dir)
    csv_text = exporter.to_csv()
    lines = csv_text.strip().split("\n")
    assert lines[0] == "timestamp,agent,action,target,severity,details"
    assert len(lines) == 5  # header + 4 events


def test_csv_sorted_chronologically(evidence_dir):
    exporter = TimelineExporter()
    exporter.load(evidence_dir)
    csv_text = exporter.to_csv()
    lines = csv_text.strip().split("\n")[1:]
    timestamps = [l.split(",")[0] for l in lines]
    assert timestamps == sorted(timestamps)


def test_ics_export(evidence_dir):
    exporter = TimelineExporter()
    exporter.load(evidence_dir)
    ics_text = exporter.to_ics()
    assert "BEGIN:VCALENDAR" in ics_text
    assert "END:VCALENDAR" in ics_text
    assert ics_text.count("BEGIN:VEVENT") == 4
    assert ics_text.count("END:VEVENT") == 4
    assert "SUMMARY:agent-1 - read" in ics_text


def test_gantt_export(evidence_dir):
    exporter = TimelineExporter()
    exporter.load(evidence_dir)
    gantt_text = exporter.to_gantt()
    data = json.loads(gantt_text)
    assert "agents" in data
    assert data["total_events"] == 4
    agent_names = [a["agent"] for a in data["agents"]]
    assert "agent-1" in agent_names
    assert "agent-2" in agent_names


def test_markdown_export(evidence_dir):
    exporter = TimelineExporter()
    exporter.load(evidence_dir)
    md = exporter.to_markdown()
    assert "| Timestamp |" in md
    assert "|-----------|" in md
    lines = [l for l in md.strip().split("\n") if l.startswith("|")]
    assert len(lines) == 6  # header + separator + 4 events


def test_export_dispatcher(evidence_dir):
    exporter = TimelineExporter()
    exporter.load(evidence_dir)
    csv_text = exporter.export("csv")
    assert "timestamp,agent" in csv_text

    md_text = exporter.export("markdown")
    assert "| Timestamp |" in md_text


def test_export_invalid_format(evidence_dir):
    exporter = TimelineExporter()
    exporter.load(evidence_dir)
    with pytest.raises(ValueError, match="Unsupported format"):
        exporter.export("xml")


def test_agent_filter(evidence_dir):
    exporter = TimelineExporter()
    exporter.load(evidence_dir, agent="agent-1")
    assert len(exporter.events) == 2
    for ev in exporter.events:
        assert ev["agent_id"] == "agent-1"


def test_since_filter(evidence_dir):
    exporter = TimelineExporter()
    exporter.load(evidence_dir, since="2024-01-15T10:05:00Z")
    assert len(exporter.events) == 2
    for ev in exporter.events:
        assert ev["timestamp"] >= "2024-01-15T10:05:00Z"


def test_empty_directory(tmp_path):
    exporter = TimelineExporter()
    exporter.load(tmp_path)
    assert len(exporter.events) == 0
    csv_text = exporter.to_csv()
    lines = csv_text.strip().split("\n")
    assert len(lines) == 1  # header only


def test_export_timeline_convenience(evidence_dir):
    csv_text = export_timeline(evidence_dir, fmt="csv")
    assert "timestamp,agent" in csv_text
    lines = csv_text.strip().split("\n")
    assert len(lines) == 5


def test_format_ics_dt_iso():
    assert _format_ics_dt("2024-01-15T10:00:00Z") == "20240115T100000Z"
    assert _format_ics_dt("2024-01-15T10:00:00.123Z") == "20240115T100000Z"


def test_format_ics_dt_empty():
    assert _format_ics_dt("") == "19700101T000000Z"


def test_combined_agent_and_since_filter(evidence_dir):
    exporter = TimelineExporter()
    exporter.load(evidence_dir, agent="agent-1", since="2024-01-15T10:05:00Z")
    assert len(exporter.events) == 1
    assert exporter.events[0]["action"] == "write"


def test_gantt_agent_grouping(evidence_dir):
    exporter = TimelineExporter()
    exporter.load(evidence_dir)
    gantt_data = json.loads(exporter.to_gantt())
    agent_1_row = next(a for a in gantt_data["agents"] if a["agent"] == "agent-1")
    assert len(agent_1_row["tasks"]) == 2
