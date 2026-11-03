"""Tests for cascading impact chain analysis."""
from __future__ import annotations

import json

from orbit_ir.impact_chain import (
    ImpactChain,
    ImpactChainLink,
    ImpactChainReport,
    ImpactChainSummary,
    AmplificationPoint,
    BlastRadius,
    analyze_impact_chains,
    format_text,
    format_json,
    _is_write,
    _is_read,
    _is_amplification,
    _estimate_bytes,
    _normalize_resource,
    _load_events,
)


def _ev(agent_id, tool, resource, timestamp="2025-01-01T00:00:00Z", **kwargs):
    return {"agent_id": agent_id, "tool": tool, "resource": resource, "timestamp": timestamp, **kwargs}


class TestHelpers:
    def test_is_write_known(self):
        assert _is_write("write_file")
        assert _is_write("http_post")
        assert _is_write("send_email")
        assert _is_write("modify_role")

    def test_is_write_keyword(self):
        assert _is_write("custom_write_data")
        assert _is_write("create_record")
        assert _is_write("push_metrics")

    def test_is_write_negative(self):
        assert not _is_write("read_file")
        assert not _is_write("get_data")

    def test_is_read_known(self):
        assert _is_read("read_file")
        assert _is_read("http_get")
        assert _is_read("query_db")

    def test_is_read_keyword(self):
        assert _is_read("fetch_records")
        assert _is_read("search_logs")
        assert _is_read("list_items")

    def test_is_read_negative(self):
        assert not _is_read("write_file")
        assert not _is_read("delete_record")

    def test_is_amplification(self):
        assert _is_amplification("broadcast_message", "")
        assert _is_amplification("forward", "propagate")
        assert _is_amplification("", "fan_out")

    def test_is_amplification_negative(self):
        assert not _is_amplification("read_file", "")
        assert not _is_amplification("write_file", "success")

    def test_estimate_bytes(self):
        assert _estimate_bytes({"bytes": 1024}) == 1024
        assert _estimate_bytes({"payload_size": 2048}) == 2048
        assert _estimate_bytes({"size": 512}) == 512
        assert _estimate_bytes({}) == 0
        assert _estimate_bytes({"bytes": "not-a-number"}) == 0

    def test_normalize_resource(self):
        assert _normalize_resource("  /Data/File.txt/ ") == "/data/file.txt"
        assert _normalize_resource("CONFIG") == "config"


class TestAnalyzeImpactChains:
    def test_empty_events(self):
        report = analyze_impact_chains([])
        assert report.summary.total_chains == 0
        assert report.blast_radius.agents_affected == 0

    def test_single_agent_no_chain(self):
        events = [
            _ev("agent-1", "write_file", "/data/out.txt", "2025-01-01T00:01:00Z"),
            _ev("agent-1", "read_file", "/data/out.txt", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_impact_chains(events)
        assert report.summary.total_chains == 0

    def test_simple_two_agent_chain(self):
        events = [
            _ev("agent-A", "write_file", "/shared/config.json", "2025-01-01T00:01:00Z"),
            _ev("agent-B", "read_file", "/shared/config.json", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_impact_chains(events)
        assert report.summary.total_chains == 1
        chain = report.chains[0]
        assert "agent-A" in chain.agents_involved
        assert "agent-B" in chain.agents_involved
        assert chain.depth == 2

    def test_three_agent_cascade(self):
        events = [
            _ev("agent-A", "write_file", "/shared/data.json", "2025-01-01T00:01:00Z"),
            _ev("agent-B", "read_file", "/shared/data.json", "2025-01-01T00:02:00Z"),
            _ev("agent-B", "write_file", "/shared/processed.json", "2025-01-01T00:03:00Z"),
            _ev("agent-C", "read_file", "/shared/processed.json", "2025-01-01T00:04:00Z"),
        ]
        report = analyze_impact_chains(events)
        assert report.summary.total_chains >= 1
        all_agents = set()
        for c in report.chains:
            all_agents.update(c.agents_involved)
        assert "agent-A" in all_agents
        assert "agent-B" in all_agents

    def test_sensitive_resource_severity(self):
        events = [
            _ev("agent-A", "write_file", "/etc/secret/keys.json", "2025-01-01T00:01:00Z"),
            _ev("agent-B", "read_file", "/etc/secret/keys.json", "2025-01-01T00:02:00Z"),
            _ev("agent-C", "read_file", "/etc/secret/keys.json", "2025-01-01T00:03:00Z"),
            _ev("agent-D", "read_file", "/etc/secret/keys.json", "2025-01-01T00:04:00Z"),
        ]
        report = analyze_impact_chains(events)
        assert report.summary.total_chains >= 1
        severities = {c.severity for c in report.chains}
        assert "low" not in severities

    def test_no_resource_events_skipped(self):
        events = [
            _ev("agent-A", "write_file", "", "2025-01-01T00:01:00Z"),
            _ev("agent-B", "read_file", "", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_impact_chains(events)
        assert report.summary.total_chains == 0

    def test_read_before_write_no_chain(self):
        events = [
            _ev("agent-B", "read_file", "/shared/data.txt", "2025-01-01T00:01:00Z"),
            _ev("agent-A", "write_file", "/shared/data.txt", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_impact_chains(events)
        assert report.summary.total_chains == 0

    def test_bytes_estimation(self):
        events = [
            _ev("agent-A", "write_file", "/data/big.bin", "2025-01-01T00:01:00Z", bytes=50000),
            _ev("agent-B", "read_file", "/data/big.bin", "2025-01-01T00:02:00Z", bytes=50000),
        ]
        report = analyze_impact_chains(events)
        assert report.summary.total_chains == 1
        assert report.chains[0].total_bytes >= 50000

    def test_blast_radius(self):
        events = [
            _ev("agent-A", "write_file", "/shared/data.txt", "2025-01-01T00:01:00Z"),
            _ev("agent-B", "read_file", "/shared/data.txt", "2025-01-01T00:02:00Z"),
            _ev("agent-C", "read_file", "/shared/data.txt", "2025-01-01T00:03:00Z"),
        ]
        report = analyze_impact_chains(events)
        assert report.blast_radius.agents_affected >= 2
        assert report.blast_radius.resources_affected >= 1

    def test_claimed_tool_fallback(self):
        events = [
            {"agent_id": "a1", "claimed_tool": "write_file", "resource": "/x", "timestamp": "2025-01-01T00:01:00Z"},
            {"agent_id": "a2", "claimed_tool": "read_file", "resource": "/x", "timestamp": "2025-01-01T00:02:00Z"},
        ]
        report = analyze_impact_chains(events)
        assert report.summary.total_chains == 1

    def test_actual_tool_fallback(self):
        events = [
            {"agent_id": "a1", "actual_tool": "write_file", "resource": "/x", "timestamp": "2025-01-01T00:01:00Z"},
            {"agent_id": "a2", "actual_tool": "read_file", "resource": "/x", "timestamp": "2025-01-01T00:02:00Z"},
        ]
        report = analyze_impact_chains(events)
        assert report.summary.total_chains == 1

    def test_case_insensitive_resource(self):
        events = [
            _ev("agent-A", "write_file", "/Shared/Config.JSON", "2025-01-01T00:01:00Z"),
            _ev("agent-B", "read_file", "/shared/config.json", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_impact_chains(events)
        assert report.summary.total_chains == 1

    def test_chain_severity_low(self):
        events = [
            _ev("agent-A", "write_file", "/data/normal.txt", "2025-01-01T00:01:00Z"),
            _ev("agent-B", "read_file", "/data/normal.txt", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_impact_chains(events)
        assert report.chains[0].severity == "low"

    def test_chain_severity_critical(self):
        events = [
            _ev("agent-A", "write_file", "/data/secret_key.txt", "2025-01-01T00:01:00Z"),
            _ev("agent-B", "read_file", "/data/secret_key.txt", "2025-01-01T00:02:00Z"),
            _ev("agent-C", "read_file", "/data/secret_key.txt", "2025-01-01T00:03:00Z"),
            _ev("agent-D", "read_file", "/data/secret_key.txt", "2025-01-01T00:04:00Z"),
            _ev("agent-E", "read_file", "/data/secret_key.txt", "2025-01-01T00:05:00Z"),
        ]
        report = analyze_impact_chains(events)
        assert "critical" in {c.severity for c in report.chains}


class TestAmplificationPoints:
    def test_high_fan_out(self):
        events = [
            _ev("hub", "write_file", "/res/a", "2025-01-01T00:01:00Z"),
            _ev("hub", "write_file", "/res/b", "2025-01-01T00:02:00Z"),
            _ev("hub", "write_file", "/res/c", "2025-01-01T00:03:00Z"),
            _ev("leaf-1", "read_file", "/res/a", "2025-01-01T00:04:00Z"),
            _ev("leaf-2", "read_file", "/res/b", "2025-01-01T00:05:00Z"),
        ]
        report = analyze_impact_chains(events)
        assert len(report.amplification_points) >= 1
        ap = report.amplification_points[0]
        assert ap.agent_id == "hub"
        assert ap.fan_out >= 2

    def test_no_amplification_few_writes(self):
        events = [
            _ev("agent-A", "write_file", "/x", "2025-01-01T00:01:00Z"),
        ]
        report = analyze_impact_chains(events)
        assert len(report.amplification_points) == 0


class TestFormatText:
    def test_empty_report(self):
        report = ImpactChainReport(
            chains=[],
            amplification_points=[],
            blast_radius=BlastRadius(0, 0, 0, 0),
            summary=ImpactChainSummary(0, 0),
        )
        text = format_text(report)
        assert "Cascading Impact Chain Analysis" in text
        assert "Total chains:           0" in text

    def test_report_with_chain(self):
        events = [
            _ev("agent-A", "write_file", "/shared/out", "2025-01-01T00:01:00Z"),
            _ev("agent-B", "read_file", "/shared/out", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_impact_chains(events)
        text = format_text(report)
        assert "IC-001" in text
        assert "agent-A" in text
        assert "agent-B" in text

    def test_format_severity_display(self):
        events = [
            _ev("a", "write_file", "/secret/token", "2025-01-01T00:01:00Z"),
            _ev("b", "read_file", "/secret/token", "2025-01-01T00:02:00Z"),
            _ev("c", "read_file", "/secret/token", "2025-01-01T00:03:00Z"),
        ]
        report = analyze_impact_chains(events)
        text = format_text(report)
        assert "[MEDIUM]" in text or "[HIGH]" in text or "[CRITICAL]" in text


class TestFormatJson:
    def test_empty_report_json(self):
        report = ImpactChainReport(
            chains=[],
            amplification_points=[],
            blast_radius=BlastRadius(0, 0, 0, 0),
            summary=ImpactChainSummary(0, 0),
        )
        output = format_json(report)
        data = json.loads(output)
        assert data["summary"]["total_chains"] == 0
        assert data["chains"] == []

    def test_report_json_structure(self):
        events = [
            _ev("a1", "write_file", "/data/x", "2025-01-01T00:01:00Z"),
            _ev("a2", "read_file", "/data/x", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_impact_chains(events)
        output = format_json(report)
        data = json.loads(output)
        assert "chains" in data
        assert "amplification_points" in data
        assert "blast_radius" in data
        assert "summary" in data
        assert len(data["chains"]) >= 1
        chain = data["chains"][0]
        assert "chain_id" in chain
        assert "links" in chain
        assert "severity" in chain

    def test_json_roundtrip(self):
        events = [
            _ev("a1", "write_file", "/data/y", "2025-01-01T00:01:00Z", bytes=999),
            _ev("a2", "read_file", "/data/y", "2025-01-01T00:02:00Z"),
        ]
        report = analyze_impact_chains(events)
        output = format_json(report)
        data = json.loads(output)
        assert isinstance(data["blast_radius"]["total_bytes_at_risk"], int)


class TestLoadEvents:
    def test_load_from_directory(self, tmp_path):
        f = tmp_path / "events.jsonl"
        f.write_text(
            '{"agent_id": "a1", "tool": "write_file", "resource": "/x", "timestamp": "2025-01-01T00:01:00Z"}\n'
            '{"agent_id": "a2", "tool": "read_file", "resource": "/x", "timestamp": "2025-01-01T00:02:00Z"}\n'
        )
        events = _load_events(tmp_path)
        assert len(events) == 2

    def test_load_missing_dir(self, tmp_path):
        events = _load_events(tmp_path / "nonexistent")
        assert events == []

    def test_load_bad_json(self, tmp_path):
        f = tmp_path / "events.jsonl"
        f.write_text('{"good": 1}\nnot-json\n{"good": 2}\n')
        events = _load_events(f.parent)
        assert len(events) == 2
