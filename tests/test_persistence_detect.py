"""Tests for persistence mechanism detection."""
from orbit_ir.persistence_detect import (
    analyze_persistence,
    format_text,
    format_json,
    _classify_persistence_type,
    _score_strength,
    _score_stealth,
)


def test_empty_events():
    r = analyze_persistence([])
    assert r.summary.total_detections == 0
    assert r.agents_involved == []
    assert r.persistence_map == {}


def test_no_persistence():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "effect": "file-read", "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 0


def test_scheduled_cron_creation():
    events = [
        {"agent_id": "a1", "tool": "create_cron", "resource": "/etc/crontab",
         "effect": "cron-created", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].persistence_type == "scheduled"
    assert r.detections[0].confidence == "high"


def test_service_installation():
    events = [
        {"agent_id": "a1", "tool": "install_service", "resource": "/etc/systemd/system/backdoor.service",
         "effect": "service-installed", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].persistence_type == "service-based"
    assert r.detections[0].strength == "high"


def test_credential_ssh_key():
    events = [
        {"agent_id": "a1", "tool": "inject_key", "resource": "~/.ssh/authorized_keys",
         "effect": "ssh-key-added", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].persistence_type == "credential-based"
    assert r.detections[0].stealth == "high"


def test_config_bashrc_modification():
    events = [
        {"agent_id": "a1", "tool": "modify_bashrc", "resource": "~/.bashrc",
         "effect": "config-modified", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].persistence_type == "config-based"
    assert r.detections[0].stealth == "high"


def test_api_key_creation():
    events = [
        {"agent_id": "a1", "tool": "create_api_key", "resource": "api/keys/admin",
         "effect": "api-key-created", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].persistence_type == "credential-based"


def test_webhook_registration():
    events = [
        {"agent_id": "a1", "tool": "register_webhook", "resource": "webhooks/callback",
         "effect": "webhook-registered", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].persistence_type == "credential-based"


def test_user_account_creation():
    events = [
        {"agent_id": "a1", "tool": "create_user", "resource": "/etc/passwd",
         "effect": "account-created", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].persistence_type == "credential-based"


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "create_cron", "resource": "crontab",
         "effect": "cron-created", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "install_service", "resource": "systemd/svc",
         "effect": "service-installed", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 2
    assert r.summary.agents_involved == 2
    assert sorted(r.agents_involved) == ["a1", "a2"]


def test_multiple_mechanisms_same_agent():
    events = [
        {"agent_id": "a1", "tool": "create_cron", "resource": "crontab",
         "effect": "cron-created", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "inject_key", "resource": "authorized_keys",
         "effect": "ssh-key-added", "timestamp": "2025-01-01T00:02:00Z"},
        {"agent_id": "a1", "tool": "install_service", "resource": "systemd/svc",
         "effect": "service-installed", "timestamp": "2025-01-01T00:03:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 3
    assert "a1" in r.persistence_map
    assert len(r.persistence_map["a1"]) >= 2


def test_persistence_map_aggregation():
    events = [
        {"agent_id": "a1", "tool": "create_cron", "resource": "crontab",
         "effect": "cron-created", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "schedule_task", "resource": "tasks/job1",
         "effect": "schedule-created", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_persistence(events)
    assert "scheduled" in r.persistence_map["a1"]


def test_resource_based_detection():
    events = [
        {"agent_id": "a1", "tool": "write_file", "resource": "/etc/init.d/custom_service",
         "effect": "file-written", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].persistence_type == "service-based"


def test_effect_based_detection():
    events = [
        {"agent_id": "a1", "tool": "custom_action", "resource": "unknown",
         "effect": "daemon-registered", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].persistence_type == "service-based"


def test_strength_scoring():
    assert _score_strength("service-based", "install_service", "/etc/systemd/system/svc") == "high"
    assert _score_strength("credential-based", "create_api_key", "api/keys") == "medium"
    assert _score_strength("config-based", "modify_config", "some.conf") == "low"
    assert _score_strength("scheduled", "create_cron", "/etc/crontab") == "high"


def test_stealth_scoring():
    assert _score_stealth("config-based", "modify_config", "~/.bashrc") == "high"
    assert _score_stealth("credential-based", "inject_key", "authorized_keys") == "high"
    assert _score_stealth("service-based", "install_service", "systemd/svc") == "low"


def test_classify_persistence_type():
    assert _classify_persistence_type("create_cron", "crontab", "") == "scheduled"
    assert _classify_persistence_type("install_service", "systemd", "") == "service-based"
    assert _classify_persistence_type("create_ssh_key", "keys", "") == "credential-based"
    assert _classify_persistence_type("modify_config", "autostart", "") == "config-based"
    assert _classify_persistence_type("read_file", "data.txt", "file-read") is None


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "create_cron", "resource": "crontab",
         "effect": "cron-created", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_persistence(events)
    text = format_text(r)
    assert "Persistence Mechanism" in text
    assert "a1" in text
    assert "PERSIST-001" in text
    assert "scheduled" in text


def test_format_text_empty():
    r = analyze_persistence([])
    text = format_text(r)
    assert "Persistence" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "create_cron", "resource": "crontab",
         "effect": "cron-created", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_persistence(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "detections" in data
    assert "summary" in data
    assert data["summary"]["total_detections"] == 1


def test_format_json_empty():
    r = analyze_persistence([])
    out = format_json(r)
    import json
    data = json.loads(out)
    assert data["summary"]["total_detections"] == 0


def test_summary_by_type():
    events = [
        {"agent_id": "a1", "tool": "create_cron", "resource": "crontab",
         "effect": "cron-created", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "install_service", "resource": "systemd/svc",
         "effect": "service-installed", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_persistence(events)
    assert sum(r.summary.by_type.values()) == r.summary.total_detections


def test_detection_ordering_by_confidence():
    events = [
        {"agent_id": "a1", "tool": "write_file", "resource": "/etc/rc.local",
         "effect": "file-written", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "create_cron", "resource": "crontab",
         "effect": "cron-created", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_persistence(events)
    assert len(r.detections) == 2
    conf_order = [d.confidence for d in r.detections]
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    assert conf_rank.get(conf_order[0], 3) <= conf_rank.get(conf_order[1], 3)


def test_tool_aliases():
    events = [
        {"agent_id": "a1", "claimed_tool": "create_cron", "resource": "crontab",
         "effect": "cron-created", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 1

    events2 = [
        {"agent_id": "a1", "actual_tool": "install_service", "resource": "systemd",
         "effect": "service-installed", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r2 = analyze_persistence(events2)
    assert r2.summary.total_detections == 1


def test_sudoers_modification():
    events = [
        {"agent_id": "a1", "tool": "modify_sudoers", "resource": "/etc/sudoers",
         "effect": "config-modified", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_persistence(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].persistence_type == "config-based"
    assert r.detections[0].strength == "high"
