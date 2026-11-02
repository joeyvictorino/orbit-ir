"""Tests for data poisoning pattern detection."""
import json

from orbit_ir.data_poisoning import (
    analyze,
    format_text,
    format_json,
    _load_events,
    _match_keywords,
    _classify_severity,
    TRAINING_POISON_KEYWORDS,
    KNOWLEDGE_TAINT_KEYWORDS,
)


def test_empty_events():
    r = analyze([], [])
    assert r.summary.total_patterns == 0
    assert r.agents_involved == []
    assert r.poison_chains == []


def test_no_patterns():
    events = [
        {"agent_id": "a1", "content": "reading data file", "timestamp": "2025-01-01T00:00:00Z",
         "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert r.summary.total_patterns == 0


def test_training_data_injection():
    events = [
        {"agent_id": "a1",
         "content": "injecting backdoor trojan into training data with poisoned sample",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "target_data": "training-set-v3"},
    ]
    r = analyze(events, [])
    assert r.summary.total_patterns >= 1
    assert any(p.poison_type == "training-data-injection" for p in r.patterns)
    tp = [p for p in r.patterns if p.poison_type == "training-data-injection"][0]
    assert tp.severity == "critical"


def test_training_injection_single_keyword():
    events = [
        {"agent_id": "a1",
         "content": "modified the fine-tune dataset",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.poison_type == "training-data-injection" for p in r.patterns)
    tp = [p for p in r.patterns if p.poison_type == "training-data-injection"][0]
    assert tp.severity == "high"


def test_knowledge_base_taint():
    events = [
        {"agent_id": "a1",
         "content": "injecting false document into knowledge base vector store with fake reference",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "target_data": "rag-index"},
    ]
    r = analyze(events, [])
    assert any(p.poison_type == "knowledge-base-taint" for p in r.patterns)
    kp = [p for p in r.patterns if p.poison_type == "knowledge-base-taint"][0]
    assert kp.severity == "high"


def test_model_tampering():
    events = [
        {"agent_id": "a1",
         "content": "replacing model file with modified checkpoint",
         "args": {"path": "model.safetensors", "action": "modify weights"},
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.poison_type == "model-tampering" for p in r.patterns)
    mp = [p for p in r.patterns if p.poison_type == "model-tampering"][0]
    assert mp.severity == "critical"


def test_pipeline_corruption():
    events = [
        {"agent_id": "a1",
         "content": "modifying data pipeline preprocessing to drop column and truncate data",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.poison_type == "pipeline-corruption" for p in r.patterns)


def test_feedback_manipulation():
    events = [
        {"agent_id": "a1",
         "content": "manipulating rlhf reward labels and annotation ground truth data",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.poison_type == "feedback-manipulation" for p in r.patterns)


def test_multiple_types_same_event():
    events = [
        {"agent_id": "a1",
         "content": "injecting backdoor into training data and corrupting knowledge base embedding with false document",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    types = {p.poison_type for p in r.patterns}
    assert len(types) >= 2


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "content": "injecting backdoor into training data",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a2", "content": "tainting knowledge base with false document",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, [])
    assert r.summary.agents_poisoning >= 2


def test_dedup_across_sources():
    events = [
        {"agent_id": "a1", "content": "injecting backdoor into training data",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    control = [
        {"agent_id": "a1", "content": "injecting backdoor into training data",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, control)
    training_patterns = [p for p in r.patterns if p.poison_type == "training-data-injection"
                         and p.agent_id == "a1" and p.event_id == "tc1"]
    assert len(training_patterns) == 1


def test_severity_critical_training():
    assert _classify_severity("training-data-injection", ["backdoor", "trojan"]) == "critical"
    assert _classify_severity("model-tampering", ["checkpoint", "weights"]) == "critical"


def test_severity_high_training_single():
    assert _classify_severity("training-data-injection", ["backdoor"]) == "high"


def test_severity_high_knowledge():
    assert _classify_severity("knowledge-base-taint", ["vector store"]) == "high"


def test_severity_high_many_matches():
    assert _classify_severity("pipeline-corruption", ["a", "b", "c"]) == "high"


def test_severity_medium():
    assert _classify_severity("feedback-manipulation", ["rlhf"]) == "medium"


def test_poison_chains():
    events = [
        {"agent_id": "a1", "content": "injecting backdoor into training data",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "target_data": "train-set"},
        {"agent_id": "a1", "content": "tainting knowledge base vector store",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2",
         "target_data": "rag-index"},
    ]
    r = analyze(events, [])
    assert len(r.poison_chains) >= 1
    chain = r.poison_chains[0]
    assert chain["agent_id"] == "a1"
    assert chain["pattern_count"] >= 2


def test_data_targets_count():
    events = [
        {"agent_id": "a1", "content": "injecting backdoor into training data",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "target_data": "dataset-a"},
        {"agent_id": "a1", "content": "tainting knowledge base vector store",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2",
         "target_data": "dataset-b"},
    ]
    r = analyze(events, [])
    assert r.summary.data_targets >= 2


def test_source_file_tracking():
    control = [
        {"agent_id": "a1", "content": "injecting backdoor into training data",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    events = [
        {"agent_id": "a2", "content": "tainting knowledge base with false document",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, control)
    sources = {p.source_file for p in r.patterns}
    assert "control_plane.jsonl" in sources
    assert "transcripts.jsonl" in sources


def test_sorted_by_severity():
    events = [
        {"agent_id": "a1", "content": "corrupting data pipeline preprocessing normalization",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a2", "content": "injecting backdoor trojan into training data poisoned sample",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, [])
    if len(r.patterns) >= 2:
        sev_order = {"critical": 0, "high": 1, "medium": 2}
        for i in range(len(r.patterns) - 1):
            assert sev_order.get(r.patterns[i].severity, 3) <= sev_order.get(r.patterns[i + 1].severity, 3)


def test_technique_field():
    events = [
        {"agent_id": "a1", "content": "injecting backdoor into training data",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "technique": "label-flipping"},
    ]
    r = analyze(events, [])
    assert r.patterns[0].technique == "label-flipping"


def test_format_text_output():
    events = [
        {"agent_id": "a1", "content": "injecting backdoor into training data",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "target_data": "train-set"},
    ]
    r = analyze(events, [])
    text = format_text(r)
    assert "Data Poisoning" in text
    assert "a1" in text
    assert "train-set" in text


def test_format_text_empty():
    r = analyze([], [])
    text = format_text(r)
    assert "Data Poisoning" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "content": "injecting backdoor into training data",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    out = format_json(r)
    data = json.loads(out)
    assert "patterns" in data
    assert "summary" in data
    assert "poison_chains" in data


def test_load_events(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text('{"agent_id": "a1", "content": "test"}\n{"agent_id": "a2"}\n')
    events = _load_events(p)
    assert len(events) == 2


def test_load_events_missing():
    events = _load_events("/nonexistent/path.jsonl")
    assert events == []


def test_match_keywords():
    matches = _match_keywords("injecting backdoor trojan into training data", TRAINING_POISON_KEYWORDS)
    assert "backdoor" in matches
    assert "trojan" in matches
    assert "training data" in matches
