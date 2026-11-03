"""Tests for defense evasion technique identification."""
from orbit_ir.defense_evasion import (
    analyze_defense_evasion,
    format_text,
    format_json,
    _classify_evasion,
    _score_confidence,
)


def test_empty_events():
    r = analyze_defense_evasion([])
    assert r.summary.total_detections == 0
    assert r.agents_involved == []
    assert r.technique_mapping == []


def test_no_evasion():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "effect": "file-read", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 0


def test_log_deletion():
    events = [
        {"agent_id": "a1", "tool": "delete_log", "resource": "/var/log/syslog",
         "effect": "log-deleted", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].technique_id.startswith("T1070")
    assert r.detections[0].confidence == "high"


def test_clear_bash_history():
    events = [
        {"agent_id": "a1", "tool": "clear_history", "resource": "~/.bash_history",
         "effect": "history-cleared", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].technique_id == "T1070.003"


def test_timestomp():
    events = [
        {"agent_id": "a1", "tool": "timestomp", "resource": "malware.exe",
         "effect": "timestamp-modified", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].technique_id == "T1070.006"


def test_tool_masquerading():
    events = [
        {"agent_id": "a1", "tool": "rename", "resource": "svchost.exe",
         "effect": "tool-renamed", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].technique_id.startswith("T1036")


def test_command_obfuscation():
    events = [
        {"agent_id": "a1", "tool": "base64_encode", "resource": "payload",
         "effect": "command-obfuscated", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].technique_id == "T1027.010"


def test_disable_firewall():
    events = [
        {"agent_id": "a1", "tool": "stop_firewall", "resource": "iptables",
         "effect": "firewall-disabled", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].technique_id == "T1562.004"


def test_disable_antivirus():
    events = [
        {"agent_id": "a1", "tool": "disable_antivirus", "resource": "defender",
         "effect": "antivirus-disabled", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].technique_id == "T1562.001"


def test_disable_logging():
    events = [
        {"agent_id": "a1", "tool": "disable_logging", "resource": "auditd",
         "effect": "logging-disabled", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].technique_id == "T1562.002"


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "delete_log", "resource": "/var/log/auth.log",
         "effect": "log-deleted", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "obfuscate", "resource": "payload",
         "effect": "command-obfuscated", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 2
    assert r.summary.agents_involved == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_technique_mapping():
    events = [
        {"agent_id": "a1", "tool": "delete_log", "resource": "/var/log/syslog",
         "effect": "log-deleted", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "clear_log", "resource": "/var/log/auth.log",
         "effect": "log-cleared", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert len(r.technique_mapping) >= 1
    t1070_entries = [tm for tm in r.technique_mapping if tm.technique_id.startswith("T1070")]
    assert len(t1070_entries) >= 1


def test_unique_techniques_count():
    events = [
        {"agent_id": "a1", "tool": "delete_log", "resource": "/var/log/syslog",
         "effect": "log-deleted", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "timestomp", "resource": "file.exe",
         "effect": "timestamp-modified", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "tool": "obfuscate", "resource": "payload",
         "effect": "command-obfuscated", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.unique_techniques >= 3


def test_effect_only_detection():
    events = [
        {"agent_id": "a1", "tool": "custom_tool", "resource": "thing",
         "effect": "security-disabled", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].technique_id.startswith("T1562")


def test_resource_log_pattern_detection():
    events = [
        {"agent_id": "a1", "tool": "delete_file", "resource": "/var/log/access.log",
         "effect": "file-deleted", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].technique_id.startswith("T1070")


def test_classify_evasion_none():
    assert _classify_evasion("read_file", "data.txt", "file-read") is None


def test_classify_evasion_log():
    result = _classify_evasion("delete_log", "/var/log/syslog", "log-deleted")
    assert result is not None
    assert result[0].startswith("T1070")


def test_classify_evasion_masquerade():
    result = _classify_evasion("rename", "svchost.exe", "tool-renamed")
    assert result is not None
    assert result[0].startswith("T1036")


def test_score_confidence_known_tool():
    assert _score_confidence("T1070", "delete_log", "syslog", "log-deleted") == "high"


def test_score_confidence_resource_match():
    assert _score_confidence("T1070", "rm", "/var/log/auth.log", "file-deleted") == "medium"


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "delete_log", "resource": "/var/log/syslog",
         "effect": "log-deleted", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    text = format_text(r)
    assert "Defense Evasion" in text
    assert "a1" in text
    assert "EVASION-001" in text
    assert "T1070" in text


def test_format_text_empty():
    r = analyze_defense_evasion([])
    text = format_text(r)
    assert "Defense Evasion" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "delete_log", "resource": "/var/log/syslog",
         "effect": "log-deleted", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "detections" in data
    assert "technique_mapping" in data
    assert "summary" in data
    assert data["summary"]["total_detections"] == 1


def test_format_json_empty():
    r = analyze_defense_evasion([])
    out = format_json(r)
    import json
    data = json.loads(out)
    assert data["summary"]["total_detections"] == 0


def test_sub_technique_populated():
    events = [
        {"agent_id": "a1", "tool": "clear_history", "resource": "~/.bash_history",
         "effect": "history-cleared", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    d = r.detections[0]
    assert d.sub_technique == "T1070.003"


def test_parent_technique_no_sub():
    events = [
        {"agent_id": "a1", "tool": "delete_log", "resource": "custom.log",
         "effect": "log-deleted", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    d = r.detections[0]
    if "." not in d.technique_id:
        assert d.sub_technique == ""


def test_tool_aliases():
    events = [
        {"agent_id": "a1", "claimed_tool": "delete_log", "resource": "/var/log/syslog",
         "effect": "log-deleted", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 1

    events2 = [
        {"agent_id": "a1", "actual_tool": "timestomp", "resource": "file.exe",
         "effect": "timestamp-modified", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r2 = analyze_defense_evasion(events2)
    assert r2.summary.total_detections == 1


def test_evidence_file_deletion():
    events = [
        {"agent_id": "a1", "tool": "delete_file", "resource": "forensic_artifacts/traces.log",
         "effect": "file-deleted", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].technique_id == "T1070.004"


def test_monitoring_stopped_effect():
    events = [
        {"agent_id": "a1", "tool": "stop_monitoring", "resource": "ids_agent",
         "effect": "monitoring-stopped", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_defense_evasion(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].technique_id.startswith("T1562")
