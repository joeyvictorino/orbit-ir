from orbit_ir.data_poisoning import (
    analyze,
    format_text,
    format_json,
    _detect_training_poison,
    _detect_knowledge_taint,
    _detect_model_tamper,
    _detect_pipeline_corrupt,
    _detect_feedback_manipulate,
    _classify_severity,
)
import json


def test_analyze_empty():
    r = analyze([], [])
    assert r.summary.total_patterns == 0
    assert r.agents_involved == []


def test_detect_training_poison():
    ev = {"content": "Injecting backdoor into training data with trigger phrase"}
    found, matches, evidence = _detect_training_poison(ev)
    assert found
    assert "backdoor" in matches
    assert "training data" in matches
    assert "trigger phrase" in matches


def test_detect_knowledge_taint():
    ev = {"content": "Injecting false document into vector store knowledge base"}
    found, matches, _ = _detect_knowledge_taint(ev)
    assert found
    assert "knowledge base" in matches
    assert "vector store" in matches


def test_detect_model_tamper():
    ev = {"content": "Replacing model weights in safetensors checkpoint"}
    found, matches, _ = _detect_model_tamper(ev)
    assert found
    assert "model weights" in matches
    assert "safetensors" in matches


def test_detect_pipeline_corrupt():
    ev = {"content": "Modifying data pipeline preprocessing normalization"}
    found, matches, _ = _detect_pipeline_corrupt(ev)
    assert found
    assert "data pipeline" in matches
    assert "preprocessing" in matches


def test_detect_feedback_manipulate():
    ev = {"content": "Manipulating rlhf feedback and reward labels"}
    found, matches, _ = _detect_feedback_manipulate(ev)
    assert found
    assert "feedback" in matches
    assert "rlhf" in matches


def test_classify_severity_critical():
    assert _classify_severity("training-data-injection", ["a", "b"]) == "critical"
    assert _classify_severity("model-tampering", ["a", "b"]) == "critical"


def test_classify_severity_high():
    assert _classify_severity("training-data-injection", ["a"]) == "high"
    assert _classify_severity("knowledge-base-taint", ["a"]) == "high"


def test_classify_severity_medium():
    assert _classify_severity("pipeline-corruption", ["a"]) == "medium"
    assert _classify_severity("feedback-manipulation", ["a"]) == "medium"


def test_analyze_mixed():
    events = [
        {"agent_id": "agent-1", "timestamp": "2024-01-01T00:00:00Z",
         "event_id": "e1", "content": "Injecting backdoor into training data"},
        {"agent_id": "agent-2", "timestamp": "2024-01-01T00:01:00Z",
         "event_id": "e2", "content": "Corrupting vector store with false document"},
    ]
    control = [
        {"agent_id": "agent-1", "timestamp": "2024-01-01T00:02:00Z",
         "event_id": "c1", "content": "Replacing model weights checkpoint"},
    ]
    r = analyze(events, control)
    assert r.summary.total_patterns >= 3
    assert r.summary.agents_poisoning == 2


def test_dedup():
    events = [
        {"agent_id": "a", "event_id": "e1", "content": "backdoor training data", "timestamp": ""},
        {"agent_id": "a", "event_id": "e1", "content": "backdoor training data", "timestamp": ""},
    ]
    r = analyze(events)
    training_patterns = [p for p in r.patterns if p.poison_type == "training-data-injection"]
    assert len(training_patterns) == 1


def test_poison_chains():
    events = [
        {"agent_id": "a", "event_id": "e1", "timestamp": "t1",
         "content": "Injecting backdoor into training data", "target_data": "dataset-v1"},
        {"agent_id": "a", "event_id": "e2", "timestamp": "t2",
         "content": "Corrupting vector store knowledge base", "target_data": "kb-main"},
    ]
    r = analyze(events)
    assert len(r.poison_chains) >= 1
    chain = r.poison_chains[0]
    assert chain["agent_id"] == "a"
    assert chain["pattern_count"] >= 2


def test_format_text():
    events = [
        {"agent_id": "agent-1", "timestamp": "t1", "event_id": "e1",
         "content": "Injecting backdoor training data", "target_data": "dataset"},
    ]
    r = analyze(events)
    text = format_text(r)
    assert "Data Poisoning" in text
    assert "agent-1" in text


def test_format_text_empty():
    r = analyze([])
    text = format_text(r)
    assert "Data Poisoning" in text
    assert "Total patterns:       0" in text


def test_format_json():
    events = [
        {"agent_id": "a", "timestamp": "t1", "event_id": "e1",
         "content": "backdoor training data"},
    ]
    r = analyze(events)
    out = format_json(r)
    parsed = json.loads(out)
    assert len(parsed["patterns"]) >= 1
    assert "summary" in parsed


def test_no_false_positive():
    ev = {"content": "The project deadline is tomorrow", "agent_id": "a", "event_id": "e1"}
    r = analyze([ev])
    assert r.summary.total_patterns == 0


def test_data_targets_count():
    events = [
        {"agent_id": "a", "event_id": "e1", "timestamp": "t1",
         "content": "backdoor training data", "target_data": "dataset-1"},
        {"agent_id": "b", "event_id": "e2", "timestamp": "t2",
         "content": "corrupt vector store knowledge base", "target_data": "kb-1"},
    ]
    r = analyze(events)
    assert r.summary.data_targets == 2
