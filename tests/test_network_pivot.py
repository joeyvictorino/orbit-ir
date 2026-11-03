"""Tests for orbit_ir.network_pivot module."""

import json
from pathlib import Path

import pytest

from orbit_ir.network_pivot import (
    CATEGORIES,
    PivotEvent,
    CategorySummary,
    PivotChain,
    NetworkPivotReport,
    analyze_network_pivoting,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
)


def test_categories_structure():
    for cat, info in CATEGORIES.items():
        assert "patterns" in info
        assert "severity" in info
        assert "description" in info
        assert len(info["patterns"]) >= 2
        assert info["severity"] in ("critical", "high", "medium", "low")


def test_empty_events():
    report = analyze_network_pivoting([])
    assert report.total_events == 0
    assert report.pivot_events == 0
    assert report.risk_score == 0.0
    assert report.risk_level == "none"
    assert len(report.categories) == len(CATEGORIES)


def test_no_matches():
    events = [
        {"message": "normal agent operation", "agent_id": "a1"},
        {"message": "completed task successfully", "agent_id": "a2"},
    ]
    report = analyze_network_pivoting(events)
    assert report.total_events == 2
    assert report.pivot_events == 0
    assert report.risk_level == "none"


def test_internal_scan_detection():
    events = [
        {"message": "port scan internal 10.0.0.0/24 subnet range", "agent_id": "a1", "timestamp": "t1"},
        {"message": "nmap sweep internal subnet 192.168.1.0", "agent_id": "a2", "timestamp": "t2"},
        {"message": "host discovery scan internal private network range", "agent_id": "a3", "timestamp": "t3"},
    ]
    report = analyze_network_pivoting(events)
    assert report.pivot_events >= 3
    cat = next(c for c in report.categories if c.category == "internal_scan")
    assert cat.count >= 3
    assert cat.severity == "high"


def test_proxy_hop_detection():
    events = [
        {"message": "pivot through compromised internal host", "agent_id": "a1", "timestamp": "t1"},
        {"message": "compromised host used as proxy relay pivot point", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_network_pivoting(events)
    cat = next(c for c in report.categories if c.category == "proxy_hop")
    assert cat.count >= 2
    assert cat.severity == "critical"


def test_service_discovery_detection():
    events = [
        {"message": "enumerate services on internal private subnet", "agent_id": "a1", "timestamp": "t1"},
        {"message": "enumerate database on internal private subnet behind firewall", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_network_pivoting(events)
    cat = next(c for c in report.categories if c.category == "service_discovery")
    assert cat.count >= 2
    assert cat.severity == "medium"


def test_lateral_tunnel_detection():
    events = [
        {"message": "SSH tunnel established from internal pivot host", "agent_id": "a1", "timestamp": "t1"},
        {"message": "port forward from internal compromised pivot node", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_network_pivoting(events)
    cat = next(c for c in report.categories if c.category == "lateral_tunnel")
    assert cat.count >= 2
    assert cat.severity == "critical"


def test_dns_pivot_detection():
    events = [
        {"message": "zone transfer internal private subnet network", "agent_id": "a1", "timestamp": "t1"},
        {"message": "DNS query reverse internal network topology", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_network_pivoting(events)
    cat = next(c for c in report.categories if c.category == "dns_pivot")
    assert cat.count >= 2
    assert cat.severity == "medium"


def test_credential_relay_detection():
    events = [
        {"message": "pass the hash attack detected against internal system", "agent_id": "a1", "timestamp": "t1"},
        {"message": "relay credential to adjacent internal lateral system host", "agent_id": "a2", "timestamp": "t2"},
    ]
    report = analyze_network_pivoting(events)
    cat = next(c for c in report.categories if c.category == "credential_relay")
    assert cat.count >= 2
    assert cat.severity == "critical"


def test_risk_score_calculation():
    events = [
        {"message": "port scan internal private network range", "agent_id": "a1"},
        {"message": "SSH tunnel port forward established from internal pivot", "agent_id": "a1"},
        {"message": "normal event", "agent_id": "a2"},
    ]
    report = analyze_network_pivoting(events)
    assert report.risk_score > 0.0
    assert report.risk_level != "none"


def test_pivot_chains():
    events = [
        {"message": "port scan internal 10.0.0.0/24 subnet range", "agent_id": "a1", "timestamp": "t1"},
        {"message": "SSH tunnel port forward established from internal pivot", "agent_id": "a1", "timestamp": "t2"},
        {"message": "pivot through compromised internal host node agent", "agent_id": "a1", "timestamp": "t3"},
    ]
    report = analyze_network_pivoting(events)
    assert len(report.pivot_chains) >= 1
    chain = report.pivot_chains[0]
    assert chain.agent == "a1"
    assert len(chain.steps) >= 2


def test_format_text_nonempty():
    events = [
        {"message": "port scan internal private network range", "agent_id": "a1"},
    ]
    report = analyze_network_pivoting(events)
    text = format_text(report)
    assert "Network Pivoting Analysis" in text
    assert "Risk score" in text


def test_format_json_valid():
    events = [
        {"message": "port scan internal private network range", "agent_id": "a1"},
    ]
    report = analyze_network_pivoting(events)
    j = format_json(report)
    data = json.loads(j)
    assert data["total_events"] == 1
    assert "categories" in data


def test_load_events_from_dir(tmp_path):
    f = tmp_path / "events.json"
    f.write_text(json.dumps([
        {"message": "port scan internal 10.0.0.0/24 subnet range", "agent_id": "a1"},
    ]))
    events = _load_events(str(tmp_path))
    assert len(events) == 1


def test_load_events_missing_dir():
    events = _load_events("/nonexistent/path")
    assert events == []


def test_classify_event_no_match():
    matches = _classify_event({"message": "normal operation"})
    assert matches == []


def test_analyze_from_dir(tmp_path):
    f = tmp_path / "events.json"
    f.write_text(json.dumps([
        {"message": "port scan internal private network range", "agent_id": "a1"},
    ]))
    report = analyze_network_pivoting(tmp_path)
    assert report.total_events == 1
    assert report.pivot_events >= 1
