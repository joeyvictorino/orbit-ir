"""Tests for token_trace module."""
import json

from orbit_ir.token_trace import (
    analyze_token_trace,
    format_text,
    format_json,
    _extract_tokens,
    _build_profile,
    TokenSnapshot,
)


def test_empty_events():
    r = analyze_token_trace([])
    assert r.summary.total_agents == 0
    assert r.summary.total_events == 0
    assert r.summary.total_tokens_consumed == 0


def test_single_agent_normal():
    events = [
        {"agent_id": "a1", "event_id": "ev1", "timestamp": "2026-01-01T00:00:00Z",
         "token_usage": {"input_tokens": 100, "output_tokens": 50}},
        {"agent_id": "a1", "event_id": "ev2", "timestamp": "2026-01-01T00:01:00Z",
         "token_usage": {"input_tokens": 120, "output_tokens": 60}},
    ]
    r = analyze_token_trace(events)
    assert r.summary.total_agents == 1
    assert r.summary.total_events == 2
    assert r.summary.total_tokens_consumed == 330
    assert r.summary.highest_consumer == "a1"


def test_extract_tokens_usage_dict():
    ev = {"token_usage": {"input_tokens": 100, "output_tokens": 200}}
    inp, out = _extract_tokens(ev)
    assert inp == 100
    assert out == 200


def test_extract_tokens_openai_format():
    ev = {"usage": {"prompt_tokens": 50, "completion_tokens": 75}}
    inp, out = _extract_tokens(ev)
    assert inp == 50
    assert out == 75


def test_extract_tokens_flat():
    ev = {"input_tokens": 30, "output_tokens": 40}
    inp, out = _extract_tokens(ev)
    assert inp == 30
    assert out == 40


def test_extract_tokens_missing():
    ev = {"agent_id": "a1"}
    inp, out = _extract_tokens(ev)
    assert inp == 0
    assert out == 0


def test_skip_zero_token_events():
    events = [
        {"agent_id": "a1", "event_id": "ev1", "timestamp": "2026-01-01T00:00:00Z"},
        {"agent_id": "a1", "event_id": "ev2", "timestamp": "2026-01-01T00:01:00Z",
         "token_usage": {"input_tokens": 100, "output_tokens": 50}},
    ]
    r = analyze_token_trace(events)
    assert r.summary.total_events == 1


def test_no_agent_id_skipped():
    events = [
        {"event_id": "ev1", "timestamp": "2026-01-01T00:00:00Z",
         "token_usage": {"input_tokens": 100, "output_tokens": 50}},
    ]
    r = analyze_token_trace(events)
    assert r.summary.total_agents == 0


def test_output_spike_detection():
    events = []
    for i in range(10):
        events.append({
            "agent_id": "a1", "event_id": f"ev{i}",
            "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            "token_usage": {"input_tokens": 100, "output_tokens": 50},
        })
    events.append({
        "agent_id": "a1", "event_id": "ev_spike",
        "timestamp": "2026-01-01T00:20:00Z",
        "token_usage": {"input_tokens": 100, "output_tokens": 5000},
    })
    r = analyze_token_trace(events)
    spike_anomalies = [a for a in r.anomalies if a.anomaly_type == "output-spike"]
    assert len(spike_anomalies) >= 1
    assert spike_anomalies[0].agent_id == "a1"


def test_high_ratio_detection():
    events = [
        {"agent_id": "a1", "event_id": f"ev{i}",
         "timestamp": f"2026-01-01T00:{i:02d}:00Z",
         "token_usage": {"input_tokens": 10, "output_tokens": 100}}
        for i in range(5)
    ]
    r = analyze_token_trace(events)
    ratio_anomalies = [a for a in r.anomalies if a.anomaly_type == "high-output-ratio"]
    assert len(ratio_anomalies) >= 1


def test_sustained_high_detection():
    events = []
    for i in range(20):
        events.append({
            "agent_id": f"norm{i % 4}", "event_id": f"n{i}",
            "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            "token_usage": {"input_tokens": 50, "output_tokens": 50},
        })
    for i in range(5):
        events.append({
            "agent_id": "hog", "event_id": f"h{i}",
            "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            "token_usage": {"input_tokens": 5000, "output_tokens": 5000},
        })
    r = analyze_token_trace(events)
    sustained = [a for a in r.anomalies if a.anomaly_type == "sustained-high-usage"]
    assert len(sustained) >= 1
    assert sustained[0].agent_id == "hog"


def test_profile_statistics():
    snaps = [
        TokenSnapshot("t1", "a1", "e1", 100, 200, 300, 2.0),
        TokenSnapshot("t2", "a1", "e2", 100, 400, 500, 4.0),
    ]
    p = _build_profile("a1", snaps)
    assert p.total_input == 200
    assert p.total_output == 600
    assert p.total_tokens == 800
    assert p.event_count == 2
    assert p.max_single_output == 400
    assert p.avg_ratio == 3.0


def test_multiple_agents_profiles():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "t1",
         "token_usage": {"input_tokens": 100, "output_tokens": 50}},
        {"agent_id": "a2", "event_id": "e2", "timestamp": "t2",
         "token_usage": {"input_tokens": 200, "output_tokens": 300}},
    ]
    r = analyze_token_trace(events)
    assert r.summary.total_agents == 2
    assert len(r.profiles) == 2
    ids = {p.agent_id for p in r.profiles}
    assert ids == {"a1", "a2"}


def test_format_text_output():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "t1",
         "token_usage": {"input_tokens": 100, "output_tokens": 50}},
    ]
    r = analyze_token_trace(events)
    text = format_text(r)
    assert "Token Usage Trace Report" in text
    assert "a1" in text


def test_format_text_empty():
    r = analyze_token_trace([])
    text = format_text(r)
    assert "Token Usage Trace Report" in text
    assert "0" in text


def test_format_json_valid():
    events = [
        {"agent_id": "a1", "event_id": "e1", "timestamp": "t1",
         "token_usage": {"input_tokens": 100, "output_tokens": 50}},
    ]
    r = analyze_token_trace(events)
    data = json.loads(format_json(r))
    assert "profiles" in data
    assert "anomalies" in data
    assert "summary" in data


def test_format_json_empty():
    data = json.loads(format_json(analyze_token_trace([])))
    assert data["summary"]["total_agents"] == 0


def test_anomaly_severity_ordering():
    events = []
    for i in range(10):
        events.append({
            "agent_id": "a1", "event_id": f"ev{i}",
            "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            "token_usage": {"input_tokens": 100, "output_tokens": 50},
        })
    events.append({
        "agent_id": "a1", "event_id": "spike",
        "timestamp": "2026-01-01T00:20:00Z",
        "token_usage": {"input_tokens": 100, "output_tokens": 10000},
    })
    r = analyze_token_trace(events)
    if len(r.anomalies) >= 2:
        severities = [a.severity for a in r.anomalies]
        order = {"high": 0, "medium": 1, "low": 2}
        assert all(order.get(severities[i], 3) <= order.get(severities[i + 1], 3)
                    for i in range(len(severities) - 1))


def test_summary_by_severity():
    events = []
    for i in range(10):
        events.append({
            "agent_id": "a1", "event_id": f"ev{i}",
            "timestamp": f"2026-01-01T00:{i:02d}:00Z",
            "token_usage": {"input_tokens": 100, "output_tokens": 50},
        })
    events.append({
        "agent_id": "a1", "event_id": "spike",
        "timestamp": "2026-01-01T00:20:00Z",
        "token_usage": {"input_tokens": 100, "output_tokens": 10000},
    })
    r = analyze_token_trace(events)
    total_by_sev = sum(r.summary.by_severity.values())
    assert total_by_sev == r.summary.anomaly_count
