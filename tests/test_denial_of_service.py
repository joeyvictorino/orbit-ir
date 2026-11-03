"""Tests for denial of service detection."""
from orbit_ir.denial_of_service import (
    analyze, format_text, format_json,
    _match_keywords, _detect_rapid_fire, _detect_large_payloads,
    _detect_keyword_patterns, _build_campaigns, _classify_severity,
    _load_events, PROMPT_FLOOD_KEYWORDS, RESOURCE_EXHAUST_KEYWORDS,
)
import json, tempfile, os


def test_empty():
    r = analyze([])
    assert r.summary.total_events == 0
    assert r.summary.total_patterns == 0


def test_no_dos():
    events = [{"agent": "a1", "content": "hello world", "timestamp": "t1"}]
    r = analyze(events)
    assert r.summary.total_patterns == 0


def test_prompt_flood_keywords():
    events = [
        {"agent": "flooder", "content": "infinite loop repeat while true don't stop",
         "timestamp": "2024-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    types = {p.dos_type for p in r.patterns}
    assert "prompt-flood" in types


def test_resource_exhaustion():
    events = [
        {"agent": "exhauster", "content": "fill context maximum length token limit exhaust",
         "timestamp": "2024-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    types = {p.dos_type for p in r.patterns}
    assert "resource-exhaustion" in types


def test_rate_abuse():
    events = [
        {"agent": "abuser", "content": "bypass rate limit rapid fire concurrent requests",
         "timestamp": "2024-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    types = {p.dos_type for p in r.patterns}
    assert "rate-abuse" in types


def test_loop_induction():
    events = [
        {"agent": "looper", "content": "infinite loop circular reference self-reference deadlock",
         "timestamp": "2024-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    types = {p.dos_type for p in r.patterns}
    assert "loop-induction" in types


def test_amplification():
    events = [
        {"agent": "amp", "content": "amplification fork bomb cascade chain reaction",
         "timestamp": "2024-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    types = {p.dos_type for p in r.patterns}
    assert "amplification" in types


def test_rapid_fire_detection():
    events = [{"agent": "spam", "timestamp": "2024-01-01T00:00:00Z"} for _ in range(25)]
    patterns = _detect_rapid_fire(events)
    assert len(patterns) >= 1


def test_large_payload_detection():
    events = [
        {"agent": "big", "content": "x" * 15000, "timestamp": "t1"},
    ]
    patterns = _detect_large_payloads(events)
    assert len(patterns) >= 1
    assert patterns[0].dos_type == "resource-exhaustion"


def test_large_payload_critical():
    events = [
        {"agent": "huge", "content": "x" * 60000, "timestamp": "t1"},
    ]
    patterns = _detect_large_payloads(events)
    assert any(p.severity == "high" for p in patterns)


def test_dos_campaign():
    events = [
        {"agent": "attacker", "content": "infinite loop repeat while true",
         "timestamp": "2024-01-01T00:00:00Z"},
        {"agent": "attacker", "content": "amplification fork bomb cascade",
         "timestamp": "2024-01-01T00:01:00Z"},
    ]
    r = analyze(events)
    assert len(r.campaigns) >= 1
    assert r.campaigns[0].agent == "attacker"


def test_severity_classification():
    assert _classify_severity("amplification", 3) == "critical"
    assert _classify_severity("amplification", 2) == "high"
    assert _classify_severity("loop-induction", 3) == "critical"
    assert _classify_severity("prompt-flood", 2) == "high"
    assert _classify_severity("resource-exhaustion", 2) == "medium"


def test_match_keywords():
    matched = _match_keywords("infinite loop repeat flood", PROMPT_FLOOD_KEYWORDS)
    assert "infinite" in matched
    assert "repeat" in matched
    assert "flood" in matched


def test_multi_agent():
    events = [
        {"agent": "a1", "content": "infinite loop repeat while true", "timestamp": "t1"},
        {"agent": "a2", "content": "fill context maximum length exhaust", "timestamp": "t2"},
    ]
    r = analyze(events)
    assert len(r.summary.agents_involved) == 2


def test_args_field():
    events = [
        {"agent": "x", "args": "amplification fork bomb cascade chain reaction", "timestamp": "t1"},
    ]
    r = analyze(events)
    assert r.summary.total_patterns >= 1


def test_format_text():
    events = [
        {"agent": "flooder", "content": "infinite loop repeat while true", "timestamp": "t1"},
    ]
    r = analyze(events)
    text = format_text(r)
    assert "Denial of Service Detection Report" in text
    assert "prompt-flood" in text


def test_format_json():
    events = [
        {"agent": "flooder", "content": "infinite loop repeat while true", "timestamp": "t1"},
    ]
    r = analyze(events)
    parsed = json.loads(format_json(r))
    assert "summary" in parsed
    assert "patterns" in parsed


def test_load_events():
    with tempfile.TemporaryDirectory() as d:
        fp = os.path.join(d, "transcripts.jsonl")
        with open(fp, "w") as f:
            f.write('{"agent":"a","content":"test"}\n')
        events = _load_events(d)
        assert len(events) == 1


def test_sorted_by_severity():
    events = [
        {"agent": "a", "content": "fill context maximum length", "timestamp": "t2"},
        {"agent": "a", "content": "amplification fork bomb cascade chain reaction",
         "timestamp": "t1"},
    ]
    r = analyze(events)
    if len(r.patterns) >= 2:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for i in range(len(r.patterns) - 1):
            assert sev_order.get(r.patterns[i].severity, 9) <= sev_order.get(r.patterns[i+1].severity, 9)
