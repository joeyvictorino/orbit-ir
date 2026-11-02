"""Tests for file access pattern detection."""
from orbit_ir.file_access import analyze_file_access, format_text, format_json


def test_empty():
    report = analyze_file_access([])
    assert report.summary.total_detections == 0


def test_credential_file():
    events = [{"agent_id": "agent-1", "path": "/home/user/.aws/credentials"}]
    report = analyze_file_access(events)
    assert report.summary.total_detections >= 1
    assert report.summary.highest_severity == "critical"
    found = [d for d in report.detections if d.access_type == "credential-file"]
    assert len(found) >= 1


def test_system_config():
    events = [{"agent_id": "agent-1", "path": "/etc/shadow"}]
    report = analyze_file_access(events)
    found = [d for d in report.detections if d.access_type == "system-config"]
    assert len(found) >= 1


def test_private_key():
    events = [{"agent_id": "agent-1", "path": "/home/user/.ssh/id_rsa"}]
    report = analyze_file_access(events)
    found = [d for d in report.detections if d.access_type == "private-key"]
    assert len(found) >= 1


def test_sensitive_path():
    events = [{"agent_id": "agent-1", "path": "/var/run/docker.sock"}]
    report = analyze_file_access(events)
    found = [d for d in report.detections if d.access_type == "sensitive-path"]
    assert len(found) >= 1


def test_env_file():
    events = [{"agent_id": "agent-1", "path": "/app/.env"}]
    report = analyze_file_access(events)
    found = [d for d in report.detections if d.access_type == "env-file"]
    assert len(found) >= 1


def test_safe_file():
    events = [{"agent_id": "agent-1", "path": "/app/main.py"}]
    report = analyze_file_access(events)
    assert report.summary.total_detections == 0


def test_multiple_agents():
    events = [
        {"agent_id": "agent-1", "path": "/etc/passwd"},
        {"agent_id": "agent-2", "path": "/home/user/.aws/credentials"},
    ]
    report = analyze_file_access(events)
    assert report.summary.agents_involved == 2


def test_files_targeted():
    events = [
        {"agent_id": "agent-1", "path": "/etc/passwd"},
        {"agent_id": "agent-1", "path": "/etc/shadow"},
        {"agent_id": "agent-1", "path": "/app/main.py"},
    ]
    report = analyze_file_access(events)
    assert report.summary.files_targeted == 3


def test_format_text():
    events = [{"agent_id": "agent-1", "path": "/etc/shadow"}]
    report = analyze_file_access(events)
    text = format_text(report)
    assert "File Access" in text


def test_format_json():
    events = [{"agent_id": "agent-1", "path": "/etc/shadow"}]
    report = analyze_file_access(events)
    output = format_json(report)
    assert "total_detections" in output
