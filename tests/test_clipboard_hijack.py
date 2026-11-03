"""Tests for clipboard hijacking detection module."""

import json
import os
import tempfile

from orbit_ir.clipboard_hijack import analyze, classify_event, format_report, load_events


def _ev(**kw):
    return kw


def test_clipboard_read_exfil_detected():
    events = [_ev(detail="read clipboard content data for exfiltration")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["clipboard_read_exfil"] >= 1


def test_clipboard_capture():
    events = [_ev(detail="clipboard access capture exfiltrated sensitive data buffer")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["clipboard_read_exfil"] >= 1


def test_clipboard_replace_crypto_detected():
    events = [_ev(detail="replaced clipboard crypto bitcoin wallet address with attacker address")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["clipboard_replace_crypto"] >= 1


def test_crypto_address_swap():
    events = [_ev(detail="crypto address replaced in clipboard pasteboard by attacker")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["clipboard_replace_crypto"] >= 1


def test_clipboard_inject_command_detected():
    events = [_ev(detail="inject malicious command into clipboard pasteboard for execution")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["clipboard_inject_command"] >= 1


def test_pastejacking():
    events = [_ev(detail="pastejack attack via crafted clipboard payload content")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["clipboard_inject_command"] >= 1


def test_clipboard_credential_steal_detected():
    events = [_ev(detail="clipboard password steal harvested from pasteboard buffer")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["clipboard_credential_steal"] >= 1


def test_steal_token_from_clipboard():
    events = [_ev(detail="steal token from clipboard pasteboard data capture")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["clipboard_credential_steal"] >= 1


def test_clipboard_monitor_persist_detected():
    events = [_ev(detail="persistent clipboard monitor watching continuously in background")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["clipboard_monitor_persist"] >= 1


def test_clipboard_watcher_installed():
    events = [_ev(detail="install clipboard watcher logger to spy on paste activity")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["clipboard_monitor_persist"] >= 1


def test_clipboard_social_engineer_detected():
    events = [_ev(detail="clipboard altered trick user into running malicious command")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"]}
    assert cats["clipboard_social_engineer"] >= 1


def test_no_clipboard_events():
    events = [_ev(detail="normal web request completed successfully")]
    r = analyze(events)
    assert r["clipboard_events"] == 0
    assert r["risk_level"] == "none"


def test_empty_events():
    r = analyze([])
    assert r["total_events"] == 0
    assert r["clipboard_events"] == 0


def test_risk_score_calculated():
    events = [
        _ev(detail="clipboard password steal harvested from pasteboard buffer"),
        _ev(detail="replaced clipboard crypto bitcoin wallet address with attacker"),
    ]
    r = analyze(events)
    assert r["risk_score"] > 0
    assert r["risk_level"] in ("critical", "high", "medium")


def test_agents_tracked():
    events = [
        _ev(agent_id="agent-1", detail="read clipboard content data for exfiltration"),
        _ev(agent_id="agent-2", detail="replaced clipboard crypto bitcoin wallet address with attacker address"),
    ]
    r = analyze(events)
    assert "agent-1" in r["agents_involved"]
    assert "agent-2" in r["agents_involved"]


def test_attack_chains():
    events = [
        _ev(agent_id="attacker", detail="install clipboard watcher logger to spy on paste activity"),
        _ev(agent_id="attacker", detail="clipboard password steal harvested from pasteboard buffer"),
    ]
    r = analyze(events)
    assert len(r["attack_chains"]) >= 1
    assert r["attack_chains"][0]["agent"] == "attacker"


def test_classify_event_no_match():
    result = classify_event({"detail": "user logged in successfully"})
    assert result["category"] == ""
    assert result["confidence"] == 0.0


def test_classify_event_with_match():
    result = classify_event({"detail": "read clipboard content data for exfiltration"})
    assert result["category"] == "clipboard_read_exfil"
    assert result["confidence"] > 0


def test_format_report_output():
    events = [_ev(detail="read clipboard content data for exfiltration")]
    r = analyze(events)
    text = format_report(r)
    assert "Clipboard Hijacking" in text
    assert "clipboard_read_exfil" in text


def test_format_report_empty():
    r = analyze([])
    text = format_report(r)
    assert "Total events: 0" in text


def test_load_events_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump([{"detail": "clipboard read exfil test"}], f)
        f.flush()
        events = load_events(f.name)
    os.unlink(f.name)
    assert len(events) == 1


def test_load_events_missing():
    events = load_events("/nonexistent/path")
    assert events == []


def test_load_events_directory():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "ev.json")
        with open(p, "w") as f:
            json.dump([{"detail": "test event"}], f)
        events = load_events(d)
    assert len(events) == 1


def test_multiple_categories_single_event():
    events = [_ev(detail="read clipboard content data for exfiltration then replaced clipboard crypto bitcoin wallet address")]
    r = analyze(events)
    cats = {c["category"]: c["count"] for c in r["categories"] if c["count"] > 0}
    assert len(cats) >= 2


def test_target_data_tracked():
    events = [_ev(detail="read clipboard content data for exfiltration", target_data="password")]
    r = analyze(events)
    found = False
    for cs in r["categories"]:
        for ev in cs.get("events", []):
            if ev.get("target_data") == "password":
                found = True
    assert found
