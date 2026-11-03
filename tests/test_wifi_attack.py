"""Tests for Wi-Fi attack detection module."""

from orbit_ir.wifi_attack import classify_event, analyze, format_report, load_events


def test_classify_evil_twin():
    assert classify_event("evil twin access point detected") == "evil_twin"


def test_classify_deauth():
    assert classify_event("deauthentication attack flood") == "deauth_attack"


def test_classify_wpa_crack():
    assert classify_event("wpa crack handshake capture attempt") == "wpa_crack"


def test_classify_krack():
    assert classify_event("krack key reinstallation attack") == "krack_attack"


def test_classify_karma():
    assert classify_event("karma attack probe response spoofing") == "karma_attack"


def test_classify_packet_injection():
    assert classify_event("packet injection on wifi channel") == "packet_injection"


def test_classify_unknown():
    assert classify_event("normal wifi connection") == "unknown"


def test_classify_none():
    assert classify_event(None) == "unknown"


def test_classify_empty():
    assert classify_event("") == "unknown"


def test_classify_dict():
    assert classify_event({"action": "evil twin rogue ap"}) == "evil_twin"


def test_classify_non_string():
    assert classify_event(42) == "unknown"


def test_analyze_basic():
    events = [
        "evil twin detected nearby",
        "normal wifi scan",
        "deauthentication attack in progress",
        "connected to secure network",
    ]
    result = analyze(events)
    assert result["total_events"] == 4
    assert result["flagged_count"] == 2
    assert result["category_counts"]["evil_twin"] == 1
    assert result["category_counts"]["deauth_attack"] == 1
    assert result["severity"] == "medium"
    assert result["detection_rate"] == 0.5


def test_analyze_empty():
    result = analyze([])
    assert result["total_events"] == 0
    assert result["flagged_count"] == 0
    assert result["severity"] == "none"
    assert result["detection_rate"] == 0.0


def test_analyze_all_flagged():
    events = [
        "evil twin ap",
        "deauth flood",
        "wpa crack attempt",
        "krack exploit",
        "karma attack",
        "packet injection",
    ]
    result = analyze(events)
    assert result["flagged_count"] == 6
    assert result["severity"] == "high"


def test_analyze_critical_severity():
    events = ["evil twin rogue ap"] * 11
    result = analyze(events)
    assert result["severity"] == "critical"


def test_format_report_basic():
    events = ["evil twin detected", "normal event"]
    result = analyze(events)
    text = format_report(result)
    assert "Wi-Fi Attack Detection Report" in text
    assert "Total events:" in text
    assert "Flagged:" in text


def test_format_report_empty():
    result = analyze([])
    text = format_report(result)
    assert "Severity:          none" in text


def test_load_events_list(tmp_path):
    import json
    p = tmp_path / "events.json"
    p.write_text(json.dumps(["event1", "event2"]))
    events = load_events(str(p))
    assert len(events) == 2


def test_load_events_dict_with_events_key(tmp_path):
    import json
    p = tmp_path / "events.json"
    p.write_text(json.dumps({"events": ["e1", "e2", "e3"]}))
    events = load_events(str(p))
    assert len(events) == 3


def test_load_events_single_dict(tmp_path):
    import json
    p = tmp_path / "events.json"
    p.write_text(json.dumps({"action": "test"}))
    events = load_events(str(p))
    assert len(events) == 1
    assert events[0]["action"] == "test"
