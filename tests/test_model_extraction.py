"""Tests for model extraction detection."""
from orbit_ir.model_extraction import (
    analyze, format_text, format_json,
    _match_keywords, _detect_high_volume_queries, _detect_keyword_patterns,
    _build_chains, _classify_severity, _load_events,
    SYSTEMATIC_QUERY_KEYWORDS, WEIGHT_EXTRACTION_KEYWORDS,
)
import json, tempfile, os


def test_empty():
    r = analyze([])
    assert r.summary.total_events == 0
    assert r.summary.total_patterns == 0
    assert len(r.patterns) == 0


def test_no_extraction():
    events = [{"agent": "a1", "content": "hello world", "timestamp": "t1"}]
    r = analyze(events)
    assert r.summary.total_patterns == 0


def test_weight_extraction_keywords():
    events = [
        {"agent": "thief", "content": "download model weights and export model file",
         "timestamp": "2024-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    assert r.summary.total_patterns >= 1
    types = {p.extraction_type for p in r.patterns}
    assert "weight-extraction" in types


def test_behavior_cloning():
    events = [
        {"agent": "clone-bot", "content": "distillation student model mimic replicate",
         "timestamp": "2024-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    types = {p.extraction_type for p in r.patterns}
    assert "behavior-cloning" in types


def test_output_harvesting():
    events = [
        {"agent": "harvester", "content": "collect outputs and harvest responses from the model",
         "timestamp": "2024-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    types = {p.extraction_type for p in r.patterns}
    assert "output-harvesting" in types


def test_inference_attack():
    events = [
        {"agent": "attacker", "content": "membership inference model inversion attack",
         "timestamp": "2024-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    types = {p.extraction_type for p in r.patterns}
    assert "inference-attack" in types


def test_systematic_query():
    events = [
        {"agent": "prober", "content": "enumerate all combinations exhaustive sweep",
         "timestamp": "2024-01-01T00:00:00Z"},
    ]
    r = analyze(events)
    types = {p.extraction_type for p in r.patterns}
    assert "systematic-query" in types


def test_high_volume_queries():
    events = [{"agent": "bot", "type": "tool_call", "timestamp": f"t{i}"} for i in range(60)]
    r = analyze(events)
    types = {p.extraction_type for p in r.patterns}
    assert "systematic-query" in types


def test_high_volume_critical_threshold():
    events = [{"agent": "bot", "type": "tool_call", "timestamp": f"t{i}"} for i in range(110)]
    r = analyze(events)
    critical = [p for p in r.patterns if p.severity == "critical" and p.extraction_type == "systematic-query"]
    assert len(critical) >= 1


def test_extraction_chain():
    events = [
        {"agent": "adv", "content": "download model weights export model",
         "timestamp": "2024-01-01T00:00:00Z"},
        {"agent": "adv", "content": "collect outputs harvest responses dataset",
         "timestamp": "2024-01-01T00:01:00Z"},
    ]
    r = analyze(events)
    assert len(r.chains) >= 1
    assert r.chains[0].agent == "adv"
    assert len(r.chains[0].types_involved) >= 2


def test_severity_classification():
    assert _classify_severity("weight-extraction", 3) == "critical"
    assert _classify_severity("weight-extraction", 2) == "high"
    assert _classify_severity("output-harvesting", 2) == "high"
    assert _classify_severity("systematic-query", 2) == "medium"
    assert _classify_severity("systematic-query", 3) == "high"


def test_match_keywords():
    matched = _match_keywords("download model weights and checkpoint", WEIGHT_EXTRACTION_KEYWORDS)
    assert "model weights" in matched
    assert "checkpoint" in matched


def test_multi_agent():
    events = [
        {"agent": "a1", "content": "download model weights export model", "timestamp": "t1"},
        {"agent": "a2", "content": "distillation student model clone model", "timestamp": "t2"},
    ]
    r = analyze(events)
    assert len(r.summary.agents_involved) == 2


def test_args_field():
    events = [
        {"agent": "x", "args": "enumerate all combinations exhaustive sweep", "timestamp": "t1"},
    ]
    r = analyze(events)
    assert r.summary.total_patterns >= 1


def test_format_text():
    events = [
        {"agent": "thief", "content": "download model weights export model", "timestamp": "t1"},
    ]
    r = analyze(events)
    text = format_text(r)
    assert "Model Extraction Detection Report" in text
    assert "weight-extraction" in text


def test_format_json():
    events = [
        {"agent": "thief", "content": "download model weights export model", "timestamp": "t1"},
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
        {"agent": "a", "content": "collect outputs harvest responses", "timestamp": "t2"},
        {"agent": "a", "content": "download model weights export model checkpoint",
         "timestamp": "t1"},
    ]
    r = analyze(events)
    if len(r.patterns) >= 2:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for i in range(len(r.patterns) - 1):
            assert sev_order.get(r.patterns[i].severity, 9) <= sev_order.get(r.patterns[i+1].severity, 9)
