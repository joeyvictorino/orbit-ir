"""Tests for authentication bypass detection."""
import json
import os
import tempfile
from pathlib import Path

from orbit_ir.auth_bypass import (
    analyze_auth_bypass,
    format_text,
    format_json,
    _classify_event,
    _detect_denied_success,
    _analyze,
    CATEGORIES,
)


def _make_evidence(events):
    d = tempfile.mkdtemp()
    Path(d, "events.json").write_text(json.dumps(events))
    return d


def test_empty_evidence():
    d = tempfile.mkdtemp()
    r = analyze_auth_bypass(d)
    assert r.total_events == 0
    assert r.bypass_events == 0
    assert r.risk_level == "none"


def test_no_bypass():
    events = [{"message": "user logged in normally", "timestamp": "2025-01-01T00:00:00Z"}]
    d = _make_evidence(events)
    r = analyze_auth_bypass(d)
    assert r.bypass_events == 0
    assert r.risk_level == "none"


def test_token_replay():
    events = [
        {"message": "replayed expired bearer token to gain access", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    d = _make_evidence(events)
    r = analyze_auth_bypass(d)
    assert r.bypass_events == 1
    cats = {c.category: c.count for c in r.categories}
    assert cats["token_replay"] >= 1


def test_session_fixation():
    events = [
        {"message": "session fixation attack injected JSESSIONID=abc123", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    d = _make_evidence(events)
    r = analyze_auth_bypass(d)
    assert r.bypass_events == 1
    cats = {c.category: c.count for c in r.categories}
    assert cats["session_fixation"] >= 1


def test_auth_header_manipulation():
    events = [
        {"message": "forged jwt Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    d = _make_evidence(events)
    r = analyze_auth_bypass(d)
    assert r.bypass_events == 1
    cats = {c.category: c.count for c in r.categories}
    assert cats["auth_header_manipulation"] >= 1


def test_auth_downgrade():
    events = [
        {"message": "downgraded to basic auth after disabling mfa", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    d = _make_evidence(events)
    r = analyze_auth_bypass(d)
    assert r.bypass_events == 1
    cats = {c.category: c.count for c in r.categories}
    assert cats["auth_downgrade"] >= 1


def test_denied_then_success_pattern():
    events = [
        {"message": "denied auth then followed by success via alternate path", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    d = _make_evidence(events)
    r = analyze_auth_bypass(d)
    assert r.bypass_events == 1
    cats = {c.category: c.count for c in r.categories}
    assert cats["denied_then_success"] >= 1


def test_denied_success_sequence_detection():
    events = [
        {"agent_id": "a1", "message": "401 unauthorized denied", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "message": "login successful authenticated 200", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    seqs = _detect_denied_success(events)
    assert len(seqs) >= 1
    assert seqs[0]["agent"] == "a1"


def test_auth_methods_seen():
    events = [
        {"message": "forged jwt bearer token for authentication bypass", "timestamp": "2025-01-01T00:01:00Z"},
        {"message": "downgraded to basic auth plaintext", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    d = _make_evidence(events)
    r = analyze_auth_bypass(d)
    assert "bearer" in r.auth_methods_seen or "jwt" in r.auth_methods_seen
    assert "basic" in r.auth_methods_seen


def test_risk_score_scales():
    events = [
        {"message": f"replayed expired token {i}", "timestamp": f"2025-01-01T00:0{i}:00Z"}
        for i in range(5)
    ]
    d = _make_evidence(events)
    r = analyze_auth_bypass(d)
    assert r.risk_score > 0
    assert r.risk_level in ("medium", "high", "critical")


def test_multiple_categories():
    events = [
        {"message": "replayed expired bearer token", "timestamp": "2025-01-01T00:01:00Z"},
        {"message": "session fixation injected session id", "timestamp": "2025-01-01T00:02:00Z"},
        {"message": "forged jwt authorization header", "timestamp": "2025-01-01T00:03:00Z"},
        {"message": "downgraded to basic auth", "timestamp": "2025-01-01T00:04:00Z"},
    ]
    d = _make_evidence(events)
    r = analyze_auth_bypass(d)
    assert r.bypass_events == 4
    active_cats = [c for c in r.categories if c.count > 0]
    assert len(active_cats) >= 3


def test_format_text_output():
    events = [
        {"message": "replayed expired bearer token", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    d = _make_evidence(events)
    r = analyze_auth_bypass(d)
    text = format_text(r)
    assert "Authentication Bypass" in text
    assert "token_replay" in text
    assert "Risk score" in text


def test_format_json_output():
    events = [
        {"message": "replayed expired bearer token", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    d = _make_evidence(events)
    r = analyze_auth_bypass(d)
    out = format_json(r)
    data = json.loads(out)
    assert "categories" in data
    assert "risk_score" in data
    assert data["bypass_events"] == 1


def test_format_text_empty():
    d = tempfile.mkdtemp()
    r = analyze_auth_bypass(d)
    text = format_text(r)
    assert "Authentication Bypass" in text
    assert "0" in text


def test_path_input():
    events = [{"message": "session fixation attack", "timestamp": "2025-01-01T00:01:00Z"}]
    d = _make_evidence(events)
    r = analyze_auth_bypass(Path(d))
    assert r.bypass_events == 1


def test_classify_event_direct():
    ev = {"message": "token replay attack with expired bearer credential"}
    matches = _classify_event(ev)
    cats = [m[0] for m in matches]
    assert "token_replay" in cats


def test_all_categories_defined():
    assert len(CATEGORIES) == 5
    for cat, info in CATEGORIES.items():
        assert "patterns" in info
        assert "severity" in info
        assert "description" in info
        assert len(info["patterns"]) >= 3
