"""Tests for orbit_ir.threat_intel — threat intelligence enrichment."""

import json
from pathlib import Path

from orbit_ir.threat_intel import (
    ThreatIntelReport,
    analyze,
    format_json,
    format_text,
)


def _write_events(tmp_path: Path, events: list[dict]) -> Path:
    p = tmp_path / "events.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return tmp_path


def test_empty_evidence(tmp_path):
    r = analyze(tmp_path)
    assert r.total_events == 0
    assert r.iocs_extracted == 0
    assert r.overall_threat_level == "none"


def test_ip_extraction(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "src_ip": "192.168.1.1"},
        {"timestamp": "2025-01-01T00:01:00Z", "dst_ip": "10.0.0.5"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.iocs_extracted >= 2
    assert r.ioc_summary["ip"] >= 2


def test_suspicious_ip_range(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "dst_ip": "203.0.113.50"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    matches = [m for m in r.matches if m.ioc_type == "ip"]
    assert len(matches) >= 1
    assert matches[0].threat_category == "suspicious_network"


def test_suspicious_tld(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "url": "http://evil-site.xyz/payload"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    domain_matches = [m for m in r.matches if m.ioc_type == "domain"]
    assert len(domain_matches) >= 1
    assert domain_matches[0].threat_category == "suspicious_domain"


def test_deep_subdomain(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "domain": "a.b.c.d.evil.com"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    dga = [m for m in r.matches if m.threat_category == "dga_candidate"]
    assert len(dga) >= 1


def test_malware_hash_prefix(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "file_hash": "deadbeef00000000000000000000000000000000"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    hash_matches = [m for m in r.matches if m.ioc_type == "hash"]
    assert len(hash_matches) >= 1
    assert hash_matches[0].severity == "critical"
    assert hash_matches[0].confidence == 0.9


def test_threat_keyword_detection(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "action": "deploy_trojan", "type": "malware"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    kw_matches = [m for m in r.matches if m.ioc_type == "keyword"]
    assert len(kw_matches) >= 1
    assert kw_matches[0].threat_category == "malware"


def test_custom_feed(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "dst_ip": "8.8.8.8"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path, custom_feeds={"my_blocklist": ["8.8.8.8"]})
    custom = [m for m in r.matches if m.source == "my_blocklist"]
    assert len(custom) == 1
    assert custom[0].confidence == 0.8


def test_deduplication(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "url": "http://bad.xyz/a"},
        {"timestamp": "2025-01-01T00:01:00Z", "url": "http://bad.xyz/b"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    domain_matches = [m for m in r.matches if m.ioc_value == "bad.xyz"]
    assert len(domain_matches) == 1


def test_overall_threat_level_critical(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "hash": "deadbeef11111111111111111111111111111111"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.overall_threat_level == "critical"


def test_overall_threat_level_low(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "agent_id": "a1", "action": "read"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    assert r.overall_threat_level in ("low", "medium")


def test_no_private_ip_matches(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "src_ip": "192.168.1.1"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    ip_matches = [m for m in r.matches if m.ioc_type == "ip" and m.ioc_value == "192.168.1.1"]
    assert len(ip_matches) == 0


def test_format_text_output(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "dst_ip": "203.0.113.10"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    text = format_text(r)
    assert "Threat Intelligence Enrichment" in text
    assert "IOC Summary" in text


def test_format_json_output(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "agent_id": "a1"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    j = json.loads(format_json(r))
    assert "total_events" in j
    assert "matches" in j
    assert "ioc_summary" in j


def test_multiple_ioc_types(tmp_path):
    events = [
        {"timestamp": "2025-01-01T00:00:00Z", "src_ip": "203.0.113.5",
         "domain": "malware.tk", "hash": "deadbeef22222222222222222222222222222222"},
    ]
    _write_events(tmp_path, events)
    r = analyze(tmp_path)
    types = {m.ioc_type for m in r.matches}
    assert "ip" in types
    assert "domain" in types
    assert "hash" in types
