"""Tests for orbit_ir.data_flow module."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from orbit_ir.data_flow import (
    DataFlowAnalyzer,
    analyze_data_flow,
    format_data_flow_text,
    _classify_sensitivity,
    _is_external,
    _is_store,
)


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    events = [
        {
            "agent_id": "agent-1",
            "dst_agent": "agent-2",
            "type": "data_transfer",
            "resource": "database/users",
            "data_type": "credential",
            "size": 1024,
            "timestamp": "2025-01-01T00:01:00Z",
        },
        {
            "agent_id": "agent-2",
            "dst_agent": "agent-3",
            "type": "api_call",
            "resource": "redis/cache",
            "data_type": "session",
            "size": 256,
            "timestamp": "2025-01-01T00:02:00Z",
        },
        {
            "agent_id": "agent-1",
            "dst_agent": "https://external-api.com",
            "type": "upload",
            "data_type": "secret_export",
            "size": 2048,
            "timestamp": "2025-01-01T00:03:00Z",
        },
        {
            "agent_id": "agent-3",
            "type": "log_write",
            "resource": "disk/logs",
            "data_type": "metric",
            "size": 128,
            "timestamp": "2025-01-01T00:04:00Z",
        },
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    return tmp_path


def test_classify_sensitivity_high():
    assert _classify_sensitivity("credential leak") == "high"
    assert _classify_sensitivity("secret key") == "high"
    assert _classify_sensitivity("password reset") == "high"
    assert _classify_sensitivity("token rotation") == "high"


def test_classify_sensitivity_medium():
    assert _classify_sensitivity("config update") == "medium"
    assert _classify_sensitivity("internal service") == "medium"


def test_classify_sensitivity_low():
    assert _classify_sensitivity("log entry") == "low"
    assert _classify_sensitivity("health check") == "low"
    assert _classify_sensitivity("metric report") == "low"


def test_classify_sensitivity_none():
    assert _classify_sensitivity("plain data transfer") == "none"


def test_is_external():
    assert _is_external("https://api.example.com") is True
    assert _is_external("external-service") is True
    assert _is_external("s3://my-bucket") is True
    assert _is_external("internal-db") is False
    assert _is_external("agent-2") is False


def test_is_store():
    assert _is_store("database/users") is True
    assert _is_store("redis/cache") is True
    assert _is_store("s3://bucket") is True
    assert _is_store("file/output.txt") is True
    assert _is_store("agent-2") is False


def test_analyzer_basic(evidence_dir: Path):
    analyzer = DataFlowAnalyzer()
    report = analyzer.analyze(evidence_dir)
    assert report.total_events == 4
    assert "agent-1" in report.agents
    assert "agent-2" in report.agents
    assert len(report.edges) > 0


def test_analyzer_detects_agents(evidence_dir: Path):
    analyzer = DataFlowAnalyzer()
    report = analyzer.analyze(evidence_dir)
    assert "agent-1" in report.agents
    assert "agent-2" in report.agents
    assert "agent-3" in report.agents


def test_analyzer_detects_sinks(evidence_dir: Path):
    analyzer = DataFlowAnalyzer()
    report = analyzer.analyze(evidence_dir)
    store_sinks = [s for s in report.sinks if _is_store(s)]
    assert len(store_sinks) > 0


def test_analyzer_exfiltration_alert(evidence_dir: Path):
    analyzer = DataFlowAnalyzer(sensitivity_threshold="medium")
    report = analyzer.analyze(evidence_dir)
    external_alerts = [a for a in report.exfiltration_alerts if "external" in a.destination.lower() or "https" in a.destination.lower()]
    assert len(external_alerts) > 0


def test_analyzer_sensitivity_summary(evidence_dir: Path):
    analyzer = DataFlowAnalyzer()
    report = analyzer.analyze(evidence_dir)
    assert isinstance(report.sensitivity_summary, dict)
    total = sum(report.sensitivity_summary.values())
    assert total == report.total_events


def test_analyzer_empty_dir(tmp_path: Path):
    analyzer = DataFlowAnalyzer()
    report = analyzer.analyze(tmp_path)
    assert report.total_events == 0
    assert report.agents == []
    assert report.edges == []
    assert report.exfiltration_alerts == []


def test_analyze_data_flow_function(evidence_dir: Path):
    result = analyze_data_flow(evidence_dir)
    assert isinstance(result, dict)
    assert result["total_events"] == 4
    assert "agents" in result
    assert "edges" in result


def test_format_data_flow_text(evidence_dir: Path):
    result = analyze_data_flow(evidence_dir)
    text = format_data_flow_text(result)
    assert "Data Flow Analysis" in text
    assert "4 events" in text


def test_edge_aggregation():
    events = [
        {"agent_id": "a1", "dst_agent": "a2", "data_type": "msg", "size": 100},
        {"agent_id": "a1", "dst_agent": "a2", "data_type": "msg", "size": 200},
        {"agent_id": "a1", "dst_agent": "a2", "data_type": "msg", "size": 50},
    ]
    analyzer = DataFlowAnalyzer()
    report = analyzer._build_report(events)
    matching = [e for e in report.edges if e.source == "a1" and e.target == "a2" and e.data_type == "msg"]
    assert len(matching) == 1
    assert matching[0].event_count == 3
    assert matching[0].total_bytes == 350


def test_no_exfiltration_for_internal_flows():
    events = [
        {"agent_id": "a1", "dst_agent": "a2", "data_type": "token", "size": 100},
    ]
    analyzer = DataFlowAnalyzer(sensitivity_threshold="low")
    report = analyzer._build_report(events)
    assert len(report.exfiltration_alerts) == 0


def test_exfiltration_threshold():
    events = [
        {"agent_id": "a1", "dst_agent": "https://external.com", "data_type": "log", "size": 50},
    ]
    analyzer_high = DataFlowAnalyzer(sensitivity_threshold="high")
    report_high = analyzer_high._build_report(events)
    assert len(report_high.exfiltration_alerts) == 0

    analyzer_low = DataFlowAnalyzer(sensitivity_threshold="low")
    report_low = analyzer_low._build_report(events)
    assert len(report_low.exfiltration_alerts) >= 1


def test_sensitivity_promotion_on_edge():
    events = [
        {"agent_id": "a1", "dst_agent": "a2", "data_type": "request", "size": 10},
        {"agent_id": "a1", "dst_agent": "a2", "data_type": "request", "size": 10, "resource": "secret/key"},
    ]
    analyzer = DataFlowAnalyzer()
    report = analyzer._build_report(events)
    matching = [e for e in report.edges if e.source == "a1" and e.target == "a2"]
    sensitivities = {e.sensitivity for e in matching}
    assert "high" in sensitivities


def test_report_to_dict(evidence_dir: Path):
    analyzer = DataFlowAnalyzer()
    report = analyzer.analyze(evidence_dir)
    d = report.to_dict()
    assert isinstance(d, dict)
    assert isinstance(d["edges"], list)
    assert isinstance(d["exfiltration_alerts"], list)


def test_jsonl_and_json(tmp_path: Path):
    events = [
        {"agent_id": "x", "dst_agent": "y", "data_type": "test"},
    ]
    (tmp_path / "a.jsonl").write_text(json.dumps(events[0]), encoding="utf-8")
    result = analyze_data_flow(tmp_path)
    assert result["total_events"] == 1


def test_string_size_handling():
    events = [
        {"agent_id": "a1", "dst_agent": "a2", "data_type": "msg", "size": "500"},
    ]
    analyzer = DataFlowAnalyzer()
    report = analyzer._build_report(events)
    matching = [e for e in report.edges if e.source == "a1"]
    assert matching[0].total_bytes == 500
