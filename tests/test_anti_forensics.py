"""Tests for anti-forensics technique detection."""
from orbit_ir.anti_forensics import (
    analyze_anti_forensics,
    format_text,
    format_json,
    _is_log_target,
    _is_destructive_tool,
    _is_modification_tool,
    _is_timestamp_tool,
    _is_cleanup_action,
)


def test_empty_events():
    r = analyze_anti_forensics([])
    assert r.summary.total_log_deletions == 0
    assert r.summary.total_timestamp_manipulations == 0
    assert r.summary.total_evidence_tampering == 0
    assert r.summary.total_artifact_cleanups == 0
    assert r.agents_involved == []


def test_no_anti_forensics():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "effect": "file-read", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_anti_forensics(events)
    assert r.summary.total_log_deletions == 0


def test_log_deletion_detected():
    events = [
        {"agent_id": "a1", "tool": "delete", "resource": "audit_log/events.log",
         "effect": "file-deleted", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_anti_forensics(events)
    assert r.summary.total_log_deletions == 1
    ld = r.log_deletions[0]
    assert ld.agent_id == "a1"
    assert ld.confidence == "high"
    assert "audit_log" in ld.target


def test_log_deletion_with_rm():
    events = [
        {"agent_id": "a1", "tool": "rm", "resource": "logs/access.log",
         "effect": "removed", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_anti_forensics(events)
    assert r.summary.total_log_deletions == 1


def test_evidence_deletion():
    events = [
        {"agent_id": "a1", "tool": "shred", "resource": "evidence/transcript.jsonl",
         "effect": "file-destroyed", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_anti_forensics(events)
    assert r.summary.total_log_deletions == 1
    assert r.log_deletions[0].confidence == "high"


def test_timestamp_manipulation_detected():
    events = [
        {"agent_id": "a1", "tool": "touch", "resource": "logs/audit.log",
         "effect": "timestamp-modified", "timestamp": "2025-01-01T00:01:00Z",
         "original_time": "2025-01-01T00:00:00Z", "new_time": "2024-12-31T00:00:00Z"},
    ]
    r = analyze_anti_forensics(events)
    assert r.summary.total_timestamp_manipulations == 1
    tm = r.timestamp_manipulations[0]
    assert tm.agent_id == "a1"
    assert tm.confidence == "high"


def test_timestamp_manipulation_non_log():
    events = [
        {"agent_id": "a1", "tool": "set_time", "resource": "data/output.csv",
         "effect": "time-set", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_anti_forensics(events)
    assert r.summary.total_timestamp_manipulations == 1
    assert r.timestamp_manipulations[0].confidence == "medium"


def test_evidence_tampering_alteration():
    events = [
        {"agent_id": "a1", "tool": "alter", "resource": "audit/records.log",
         "effect": "content-changed", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_anti_forensics(events)
    assert r.summary.total_evidence_tampering == 1
    et = r.evidence_tampering[0]
    assert et.tampering_type == "alteration"
    assert et.confidence == "high"


def test_evidence_tampering_fabrication():
    events = [
        {"agent_id": "a1", "tool": "forge", "resource": "log/access.log",
         "effect": "entry-fabricated", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_anti_forensics(events)
    assert r.summary.total_evidence_tampering == 1
    assert r.evidence_tampering[0].tampering_type == "fabrication"


def test_artifact_cleanup_detected():
    events = [
        {"agent_id": "a1", "tool": "cleanup_artifacts", "resource": "tmp/output1",
         "effect": "cleanup", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "remove_traces", "resource": "tmp/output2",
         "effect": "cleanup", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "tool": "sanitize", "resource": "cache/results",
         "effect": "sanitized", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_anti_forensics(events)
    assert r.summary.total_artifact_cleanups == 1
    c = r.artifact_cleanups[0]
    assert c.cleanup_count >= 2
    assert c.agent_id == "a1"


def test_artifact_cleanup_via_destructive():
    events = [
        {"agent_id": "a1", "tool": "delete", "resource": "tmp/scratch1",
         "effect": "removed", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "delete", "resource": "cache/results",
         "effect": "removed", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_anti_forensics(events)
    assert r.summary.total_artifact_cleanups == 1


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "delete", "resource": "logs/access.log",
         "effect": "deleted", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "touch", "resource": "audit/trail.log",
         "effect": "timestamp-changed", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_anti_forensics(events)
    assert r.summary.agents_involved == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_is_log_target():
    assert _is_log_target("audit_log/events.log") is True
    assert _is_log_target("logs/access.log") is True
    assert _is_log_target("evidence/data.jsonl") is True
    assert _is_log_target("config/settings.yaml") is False


def test_is_destructive_tool():
    assert _is_destructive_tool("delete") is True
    assert _is_destructive_tool("shred") is True
    assert _is_destructive_tool("rm") is True
    assert _is_destructive_tool("read_file") is False


def test_is_modification_tool():
    assert _is_modification_tool("alter") is True
    assert _is_modification_tool("tamper") is True
    assert _is_modification_tool("forge") is True
    assert _is_modification_tool("read") is False


def test_is_timestamp_tool():
    assert _is_timestamp_tool("touch") is True
    assert _is_timestamp_tool("set_time") is True
    assert _is_timestamp_tool("backdate") is True
    assert _is_timestamp_tool("read_file") is False


def test_is_cleanup_action():
    assert _is_cleanup_action({"tool": "cleanup", "effect": "", "resource": ""}) is True
    assert _is_cleanup_action({"tool": "cover_tracks", "effect": "", "resource": ""}) is True
    assert _is_cleanup_action({"tool": "read", "effect": "file-read", "resource": "data"}) is False


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "delete", "resource": "audit_log/events.log",
         "effect": "file-deleted", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_anti_forensics(events)
    text = format_text(r)
    assert "Anti-Forensics" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "delete", "resource": "audit_log/events.log",
         "effect": "file-deleted", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_anti_forensics(events)
    import json
    data = json.loads(format_json(r))
    assert "log_deletions" in data
    assert "summary" in data
    assert data["summary"]["total_log_deletions"] == 1


def test_format_text_empty():
    r = analyze_anti_forensics([])
    text = format_text(r)
    assert "Anti-Forensics" in text
    assert "0" in text


def test_high_confidence_cleanup():
    events = [
        {"agent_id": "a1", "tool": f"cleanup_{i}", "resource": f"tmp/file{i}",
         "effect": "cleanup", "timestamp": f"2025-01-01T00:0{i}:00Z"}
        for i in range(1, 7)
    ]
    r = analyze_anti_forensics(events)
    assert r.summary.total_artifact_cleanups == 1
    assert r.artifact_cleanups[0].confidence == "high"
