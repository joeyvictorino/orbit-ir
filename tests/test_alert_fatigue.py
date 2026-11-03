"""Tests for alert_fatigue module."""
import json

from orbit_ir.alert_fatigue import (
    analyze_alert_fatigue,
    format_text,
    format_json,
    _classify_alert_type,
    _extract_severity,
    _normalize_message,
    _extract_alerts,
    _find_duplicates,
    AlertRecord,
)


def test_empty_events():
    r = analyze_alert_fatigue([])
    assert r.summary.total_agents == 0
    assert r.summary.total_alerts == 0
    assert r.summary.fatigue_score == 0


def test_classify_alert_type_auth():
    assert _classify_alert_type("Failed login attempt from user") == "authentication"


def test_classify_alert_type_access():
    assert _classify_alert_type("Access denied for resource") == "access-violation"


def test_classify_alert_type_anomaly():
    assert _classify_alert_type("Unusual traffic pattern detected") == "anomaly"


def test_classify_alert_type_resource():
    assert _classify_alert_type("CPU usage exceeded threshold") == "resource"


def test_classify_alert_type_network():
    assert _classify_alert_type("Connection timeout on port 443") == "network"


def test_classify_alert_type_security():
    assert _classify_alert_type("SQL injection attack detected") == "security"


def test_classify_alert_type_general():
    assert _classify_alert_type("Something happened") == "general"


def test_extract_severity():
    assert _extract_severity("CRITICAL failure") == "critical"
    assert _extract_severity("High priority alert") == "high"
    assert _extract_severity("Medium risk detected") == "medium"
    assert _extract_severity("Low priority notice") == "low"
    assert _extract_severity("Something happened") == "medium"


def test_normalize_message():
    msg = "Error from 192.168.1.1 at 2026-01-01T00:00:00Z with id a1b2c3d4e5f6"
    norm = _normalize_message(msg)
    assert "<IP>" in norm
    assert "<TS>" in norm
    assert "<ID>" in norm


def test_single_agent_alerts():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "alert": "Failed login attempt"},
        {"agent_id": "a1", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z",
         "alert": "Failed login attempt"},
    ]
    r = analyze_alert_fatigue(events)
    assert r.summary.total_agents == 1
    assert r.summary.total_alerts == 2
    assert len(r.clusters) == 1
    assert r.clusters[0].count == 2


def test_no_duplicates():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "alert": "First unique alert"},
        {"agent_id": "a1", "event_id": "e2", "timestamp": "2026-01-01T00:01:00Z",
         "alert": "Second unique alert"},
    ]
    r = analyze_alert_fatigue(events)
    assert r.summary.duplicate_clusters == 0
    assert r.summary.total_duplicates == 0


def test_high_duplicate_anomaly():
    events = [
        {"agent_id": "a1", "event_id": f"e{i}", "timestamp": f"2026-01-01T00:{i:02d}:00Z",
         "alert": "Same alert repeated"}
        for i in range(12)
    ]
    r = analyze_alert_fatigue(events)
    has_high_dup = any(a.anomaly_type == "high-duplicate-rate" for a in r.anomalies)
    assert has_high_dup


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "alert": "Alert from agent 1"},
        {"agent_id": "a2", "event_id": "e2", "timestamp": "2026-01-01T00:00:00Z",
         "alert": "Alert from agent 2"},
    ]
    r = analyze_alert_fatigue(events)
    assert r.summary.total_agents == 2
    assert len(r.agents_involved) == 2


def test_profiles_populated():
    events = [
        {"agent_id": "a1", "event_id": f"e{i}", "timestamp": f"2026-01-01T00:{i:02d}:00Z",
         "alert": f"Alert number {i} about login failure"}
        for i in range(5)
    ]
    r = analyze_alert_fatigue(events)
    assert len(r.profiles) == 1
    p = r.profiles[0]
    assert p.agent_id == "a1"
    assert p.total_alerts == 5


def test_events_without_agent_id_skipped():
    events = [
        {"event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "alert": "No agent id"},
    ]
    r = analyze_alert_fatigue(events)
    assert r.summary.total_agents == 0


def test_message_field_fallback():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "message": "Alert via message field"},
    ]
    r = analyze_alert_fatigue(events)
    assert r.summary.total_alerts == 1


def test_content_field_fallback():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "content": "Alert via content field"},
    ]
    r = analyze_alert_fatigue(events)
    assert r.summary.total_alerts == 1


def test_format_text_nonempty():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "alert": "Test alert"},
    ]
    r = analyze_alert_fatigue(events)
    text = format_text(r)
    assert "Alert Fatigue" in text
    assert "Total alerts" in text


def test_format_text_empty():
    r = analyze_alert_fatigue([])
    text = format_text(r)
    assert "Total alerts" in text


def test_format_json_roundtrip():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
         "alert": "Test alert for JSON"},
    ]
    r = analyze_alert_fatigue(events)
    j = format_json(r)
    data = json.loads(j)
    assert "clusters" in data
    assert "anomalies" in data
    assert "profiles" in data
    assert "summary" in data


def test_fatigue_score_degrades_with_duplicates():
    events = [
        {"agent_id": "a1", "event_id": f"e{i}", "timestamp": f"2026-01-01T00:{i:02d}:00Z",
         "alert": "Repeated alert signal"}
        for i in range(20)
    ]
    r = analyze_alert_fatigue(events)
    assert r.summary.fatigue_score < 100


def test_most_noisy_agent():
    events = [
        {"agent_id": "a1", "event_id": f"e{i}", "timestamp": f"2026-01-01T00:{i:02d}:00Z",
         "alert": f"Alert {i}"}
        for i in range(5)
    ] + [
        {"agent_id": "a2", "event_id": f"f{i}", "timestamp": f"2026-01-01T00:{i:02d}:00Z",
         "alert": f"Other alert {i}"}
        for i in range(2)
    ]
    r = analyze_alert_fatigue(events)
    assert r.summary.most_noisy_agent == "a1"
