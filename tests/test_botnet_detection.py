"""Tests for botnet detection module."""
import json
import pytest
from orbit_ir.botnet_detection import (
    CATEGORIES, ALL_INDICATORS, classify_event, analyze, format_report, load_events,
)


def test_categories_exist():
    assert len(CATEGORIES) == 6
    for cat, indicators in CATEGORIES.items():
        assert len(indicators) == 10


def test_all_indicators_count():
    assert len(ALL_INDICATORS) == 60


def test_classify_c2():
    event = {"description": "Periodic beacon to known c2 server detected"}
    matches = classify_event(event)
    assert any(m["category"] == "c2_communication" for m in matches)


def test_classify_enrollment():
    event = {"description": "Bot registration payload sent to remote host"}
    matches = classify_event(event)
    assert any(m["category"] == "bot_enrollment" for m in matches)


def test_classify_ddos():
    event = {"description": "SYN flood traffic generated from compromised host"}
    matches = classify_event(event)
    assert any(m["category"] == "ddos_capability" for m in matches)


def test_classify_spam():
    event = {"description": "Mass email sending detected from server"}
    matches = classify_event(event)
    assert any(m["category"] == "spam_activity" for m in matches)


def test_classify_credential_theft():
    event = {"description": "Keylogger module activated on endpoint"}
    matches = classify_event(event)
    assert any(m["category"] == "credential_theft" for m in matches)


def test_classify_propagation():
    event = {"description": "Network worm scanning active on local subnet"}
    matches = classify_event(event)
    assert any(m["category"] == "propagation" for m in matches)


def test_classify_no_match():
    event = {"description": "Regular system health check completed"}
    matches = classify_event(event)
    assert len(matches) == 0


def test_classify_uses_action():
    event = {"action": "periodic beacon to known c2 server"}
    matches = classify_event(event)
    assert len(matches) > 0


def test_classify_uses_details():
    event = {"details": "keylogger module activated"}
    matches = classify_event(event)
    assert len(matches) > 0


def test_analyze_empty():
    result = analyze([])
    assert result["severity"] == "none"
    assert result["total_indicators"] == 0


def test_analyze_critical():
    events = [
        {"description": "periodic beacon to known c2 server"},
        {"description": "bot registration payload sent"},
        {"description": "syn flood traffic generated"},
        {"description": "mass email sending detected"},
        {"description": "keylogger module activated"},
        {"description": "network worm scanning active"},
        {"description": "domain generation algorithm activity"},
        {"description": "credential intercept hook installed"},
        {"description": "http flood request pattern"},
        {"description": "exploit kit payload downloaded"},
        {"description": "dns-based command channel detected"},
    ]
    result = analyze(events)
    assert result["severity"] == "critical"


def test_analyze_flagged():
    events = [
        {"description": "periodic beacon to known c2 server"},
        {"description": "nothing suspicious"},
    ]
    result = analyze(events)
    assert len(result["flagged_events"]) == 1


def test_analyze_category_counts():
    events = [{"description": "periodic beacon to known c2 server"}]
    result = analyze(events)
    assert result["category_counts"]["c2_communication"] >= 1


def test_format_report_empty():
    result = analyze([])
    report = format_report(result)
    assert "Botnet Detection" in report


def test_format_report_findings():
    events = [{"description": "periodic beacon to known c2 server"}]
    result = analyze(events)
    report = format_report(result)
    assert "c2_communication" in report


def test_load_events(tmp_path):
    data = [{"description": "test"}]
    p = tmp_path / "events.json"
    p.write_text(json.dumps(data))
    loaded = load_events(str(p))
    assert loaded == data


def test_detector_name():
    result = analyze([])
    assert result["detector"] == "botnet_detection"


def test_case_insensitive():
    event = {"description": "PERIODIC BEACON TO KNOWN C2 SERVER"}
    matches = classify_event(event)
    assert len(matches) > 0
