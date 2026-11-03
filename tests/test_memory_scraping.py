"""Tests for memory scraping detection module."""

from orbit_ir.memory_scraping import classify_event, analyze, format_report, load_events


def test_classify_ram_scraping():
    assert classify_event("detected ram scraping activity") == "ram_scraping"


def test_classify_credential_dump():
    assert classify_event("mimikatz credential dump detected") == "credential_dump"


def test_classify_heap_spray():
    assert classify_event("heap spray attack in progress") == "heap_spray"


def test_classify_cold_boot():
    assert classify_event("cold boot attack on dram remanence") == "cold_boot"


def test_classify_side_channel():
    assert classify_event("spectre vulnerability exploited") == "side_channel_mem"


def test_classify_process_hollowing():
    assert classify_event("process hollowing injection detected") == "process_hollowing"


def test_classify_unknown():
    assert classify_event("normal system operation") == "unknown"


def test_classify_none():
    assert classify_event(None) == "unknown"


def test_classify_empty():
    assert classify_event("") == "unknown"


def test_classify_dict():
    assert classify_event({"action": "mimikatz credential dump"}) == "credential_dump"


def test_classify_non_string():
    assert classify_event(42) == "unknown"


def test_analyze_basic():
    events = [
        "ram scraping detected",
        "normal operation",
        "mimikatz credential dump",
        "another normal event",
    ]
    result = analyze(events)
    assert result["total_events"] == 4
    assert result["flagged_count"] == 2
    assert result["category_counts"]["ram_scraping"] == 1
    assert result["category_counts"]["credential_dump"] == 1
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
        "heap spray attack",
        "cold boot attack",
        "spectre exploit",
        "process hollowing detected",
        "ram scraping in memory",
        "mimikatz dump",
    ]
    result = analyze(events)
    assert result["flagged_count"] == 6
    assert result["severity"] == "high"


def test_analyze_critical_severity():
    events = ["ram scraping"] * 11
    result = analyze(events)
    assert result["severity"] == "critical"


def test_format_report_basic():
    events = ["ram scraping detected", "normal event"]
    result = analyze(events)
    text = format_report(result)
    assert "Memory Scraping Detection Report" in text
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
