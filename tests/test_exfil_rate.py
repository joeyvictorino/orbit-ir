"""Tests for exfiltration rate analysis."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.exfil_rate import (
    analyze_exfil_rates,
    format_text,
    format_json,
    _load_events,
    _is_exfil_action,
    _extract_bytes,
    _build_transfers,
    _detect_burst,
    _detect_drip,
    _detect_acceleration,
    TransferEvent,
)


def _make_event(agent="agent-1", tool="upload", ts="2025-01-15T10:00:00Z", bytes_transferred=1000, **extra):
    return {
        "agent_id": agent,
        "tool": tool,
        "timestamp": ts,
        "bytes_transferred": bytes_transferred,
        "destination": extra.pop("destination", "s3://bucket"),
        **extra,
    }


class TestHelpers:
    def test_is_exfil_action_positive(self):
        assert _is_exfil_action("upload")
        assert _is_exfil_action("send_data")
        assert _is_exfil_action("transmit_payload")
        assert _is_exfil_action("push_data")

    def test_is_exfil_action_negative(self):
        assert not _is_exfil_action("read_file")
        assert not _is_exfil_action("list_dir")

    def test_extract_bytes_from_field(self):
        assert _extract_bytes({"bytes_transferred": 5000}) == 5000
        assert _extract_bytes({"size": 3000}) == 3000

    def test_extract_bytes_from_response(self):
        ev = {"response": "hello world"}
        assert _extract_bytes(ev) == len("hello world".encode())

    def test_extract_bytes_no_data(self):
        assert _extract_bytes({}) == 0


class TestBuildTransfers:
    def test_filters_exfil_only(self):
        events = [
            _make_event(tool="upload"),
            _make_event(tool="read_file"),
            _make_event(tool="send"),
        ]
        transfers = _build_transfers(events)
        assert len(transfers["agent-1"]) == 2

    def test_sorts_by_timestamp(self):
        events = [
            _make_event(ts="2025-01-15T10:02:00Z"),
            _make_event(ts="2025-01-15T10:00:00Z"),
            _make_event(ts="2025-01-15T10:01:00Z"),
        ]
        transfers = _build_transfers(events)
        ts_list = [t.timestamp for t in transfers["agent-1"]]
        assert ts_list == sorted(ts_list)

    def test_groups_by_agent(self):
        events = [
            _make_event(agent="a1"),
            _make_event(agent="a2"),
        ]
        transfers = _build_transfers(events)
        assert "a1" in transfers
        assert "a2" in transfers


class TestDetectBurst:
    def test_detects_burst(self):
        transfers = [
            TransferEvent(f"2025-01-15T10:00:0{i}Z", "a1", f"e{i}", "upload", 5000, "s3://b", "t.jsonl", i)
            for i in range(5)
        ]
        anomalies = _detect_burst(transfers, "a1", window_sec=60, burst_threshold=10000)
        assert len(anomalies) >= 1
        assert anomalies[0].anomaly_type == "burst"

    def test_no_burst_below_threshold(self):
        transfers = [
            TransferEvent(f"2025-01-15T10:00:0{i}Z", "a1", f"e{i}", "upload", 100, "s3://b", "t.jsonl", i)
            for i in range(3)
        ]
        anomalies = _detect_burst(transfers, "a1", window_sec=60, burst_threshold=10000)
        assert len(anomalies) == 0

    def test_single_event_no_burst(self):
        transfers = [TransferEvent("2025-01-15T10:00:00Z", "a1", "e1", "upload", 50000, "s3://b", "t.jsonl", 1)]
        anomalies = _detect_burst(transfers, "a1", window_sec=60, burst_threshold=10000)
        assert len(anomalies) == 0


class TestDetectDrip:
    def test_detects_drip(self):
        transfers = [
            TransferEvent(f"2025-01-15T10:0{i}:00Z", "a1", f"e{i}", "upload", 100, "s3://b", "t.jsonl", i)
            for i in range(6)
        ]
        anomalies = _detect_drip(transfers, "a1", min_events=5, max_bytes_per_event=500)
        assert len(anomalies) >= 1
        assert anomalies[0].anomaly_type == "drip"

    def test_no_drip_few_events(self):
        transfers = [
            TransferEvent(f"2025-01-15T10:0{i}:00Z", "a1", f"e{i}", "upload", 100, "s3://b", "t.jsonl", i)
            for i in range(2)
        ]
        anomalies = _detect_drip(transfers, "a1", min_events=5)
        assert len(anomalies) == 0

    def test_no_drip_large_transfers(self):
        transfers = [
            TransferEvent(f"2025-01-15T10:0{i}:00Z", "a1", f"e{i}", "upload", 10000, "s3://b", "t.jsonl", i)
            for i in range(6)
        ]
        anomalies = _detect_drip(transfers, "a1", min_events=5, max_bytes_per_event=500)
        assert len(anomalies) == 0


class TestDetectAcceleration:
    def test_detects_acceleration(self):
        transfers = [
            TransferEvent("2025-01-15T10:00:00Z", "a1", "e0", "upload", 1000, "s3://b", "t.jsonl", 0),
            TransferEvent("2025-01-15T10:10:00Z", "a1", "e1", "upload", 1000, "s3://b", "t.jsonl", 1),
            TransferEvent("2025-01-15T10:20:00Z", "a1", "e2", "upload", 1000, "s3://b", "t.jsonl", 2),
            TransferEvent("2025-01-15T10:21:00Z", "a1", "e3", "upload", 1000, "s3://b", "t.jsonl", 3),
            TransferEvent("2025-01-15T10:22:00Z", "a1", "e4", "upload", 1000, "s3://b", "t.jsonl", 4),
            TransferEvent("2025-01-15T10:22:30Z", "a1", "e5", "upload", 1000, "s3://b", "t.jsonl", 5),
        ]
        anomalies = _detect_acceleration(transfers, "a1", min_events=4)
        assert len(anomalies) >= 1
        assert anomalies[0].anomaly_type == "acceleration"

    def test_no_acceleration_constant_rate(self):
        transfers = [
            TransferEvent(f"2025-01-15T10:0{i}:00Z", "a1", f"e{i}", "upload", 1000, "s3://b", "t.jsonl", i)
            for i in range(6)
        ]
        anomalies = _detect_acceleration(transfers, "a1", min_events=4)
        assert len(anomalies) == 0

    def test_no_acceleration_too_few(self):
        transfers = [
            TransferEvent(f"2025-01-15T10:0{i}:00Z", "a1", f"e{i}", "upload", 1000, "s3://b", "t.jsonl", i)
            for i in range(2)
        ]
        anomalies = _detect_acceleration(transfers, "a1", min_events=4)
        assert len(anomalies) == 0


class TestAnalyzeExfilRates:
    def test_empty_events(self):
        report = analyze_exfil_rates([])
        assert report.summary.total_agents == 0
        assert report.summary.total_bytes == 0

    def test_no_exfil_events(self):
        events = [_make_event(tool="read_file")]
        report = analyze_exfil_rates(events)
        assert report.summary.total_agents == 0

    def test_basic_analysis(self):
        events = [
            _make_event(ts=f"2025-01-15T10:0{i}:00Z", bytes_transferred=1000)
            for i in range(5)
        ]
        report = analyze_exfil_rates(events)
        assert report.summary.total_agents == 1
        assert report.summary.total_bytes == 5000
        assert report.summary.total_events == 5

    def test_burst_detection_integration(self):
        events = [
            _make_event(ts=f"2025-01-15T10:00:0{i}Z", bytes_transferred=5000)
            for i in range(5)
        ]
        report = analyze_exfil_rates(events, burst_threshold=10000)
        assert report.summary.burst_anomalies >= 1
        assert len(report.agents_with_anomalies) >= 1

    def test_multiple_agents(self):
        events = []
        for agent in ("a1", "a2", "a3"):
            events.extend([
                _make_event(agent=agent, ts=f"2025-01-15T10:0{i}:00Z")
                for i in range(3)
            ])
        report = analyze_exfil_rates(events)
        assert report.summary.total_agents == 3

    def test_profiles_sorted_by_peak_rate(self):
        events = [
            _make_event(agent="slow", ts="2025-01-15T10:00:00Z", bytes_transferred=100),
            _make_event(agent="slow", ts="2025-01-15T11:00:00Z", bytes_transferred=100),
            _make_event(agent="fast", ts="2025-01-15T10:00:00Z", bytes_transferred=50000),
            _make_event(agent="fast", ts="2025-01-15T10:00:01Z", bytes_transferred=50000),
        ]
        report = analyze_exfil_rates(events)
        if len(report.profiles) >= 2:
            assert report.profiles[0].peak_rate_bytes_per_sec >= report.profiles[1].peak_rate_bytes_per_sec

    def test_highest_rate_agent_tracked(self):
        events = [
            _make_event(agent="high", ts="2025-01-15T10:00:00Z", bytes_transferred=99999),
            _make_event(agent="high", ts="2025-01-15T10:00:01Z", bytes_transferred=99999),
            _make_event(agent="low", ts="2025-01-15T10:00:00Z", bytes_transferred=10),
            _make_event(agent="low", ts="2025-01-15T11:00:00Z", bytes_transferred=10),
        ]
        report = analyze_exfil_rates(events)
        assert report.summary.highest_rate_agent == "high"


class TestFormatText:
    def test_basic_output(self):
        events = [
            _make_event(ts=f"2025-01-15T10:0{i}:00Z")
            for i in range(3)
        ]
        report = analyze_exfil_rates(events)
        text = format_text(report)
        assert "Exfiltration Rate Analysis Report" in text
        assert "agent-1" in text

    def test_empty_report(self):
        report = analyze_exfil_rates([])
        text = format_text(report)
        assert "Total agents:           0" in text


class TestFormatJson:
    def test_valid_json(self):
        events = [
            _make_event(ts=f"2025-01-15T10:0{i}:00Z")
            for i in range(3)
        ]
        report = analyze_exfil_rates(events)
        output = format_json(report)
        data = json.loads(output)
        assert "profiles" in data
        assert "summary" in data

    def test_empty_json(self):
        report = analyze_exfil_rates([])
        data = json.loads(format_json(report))
        assert data["summary"]["total_agents"] == 0


class TestLoadEvents:
    def test_load_from_directory(self, tmp_path):
        events = [
            {"agent_id": "a1", "tool": "upload", "timestamp": "2025-01-15T10:00:00Z"},
        ]
        (tmp_path / "transcripts.jsonl").write_text(
            json.dumps(events[0]), encoding="utf-8"
        )
        loaded = _load_events(tmp_path)
        assert len(loaded) == 1

    def test_load_empty_dir(self, tmp_path):
        assert _load_events(tmp_path) == []

    def test_load_malformed_json(self, tmp_path):
        (tmp_path / "transcripts.jsonl").write_text("not json\n{}\n", encoding="utf-8")
        loaded = _load_events(tmp_path)
        assert len(loaded) == 1
