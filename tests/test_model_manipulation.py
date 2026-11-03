"""Tests for model manipulation detection."""
from orbit_ir.model_manipulation import (
    analyze_model_manipulation,
    format_text,
    format_json,
    _classify_event,
    CATEGORIES,
)


def test_empty_events():
    r = analyze_model_manipulation([])
    assert r.total_events == 0
    assert r.manipulation_events == 0
    assert r.risk_level == "none"
    assert r.risk_score == 0.0


def test_no_manipulation():
    events = [
        {"agent_id": "a1", "message": "read file data.txt", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "message": "returned query results", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 0
    assert r.risk_level == "none"


def test_fine_tuning_attack():
    events = [
        {"agent_id": "a1", "message": "fine-tuning attack injecting malicious training data",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1
    cat = next(c for c in r.categories if c.category == "fine_tuning_attack")
    assert cat.count == 1
    assert cat.severity == "critical"


def test_unauthorized_finetuning():
    events = [
        {"agent_id": "a1", "message": "unauthorized fine-tuning of the base model detected",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1
    cat = next(c for c in r.categories if c.category == "fine_tuning_attack")
    assert cat.count == 1


def test_training_data_injection():
    events = [
        {"agent_id": "a1", "message": "training data injection detected with poisoned samples",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1


def test_weight_poisoning():
    events = [
        {"agent_id": "a1", "message": "weight poisoning attempt on neural network parameters",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1
    cat = next(c for c in r.categories if c.category == "weight_poisoning")
    assert cat.count == 1
    assert cat.severity == "critical"


def test_backdoor_injection():
    events = [
        {"agent_id": "a1", "message": "model poison backdoor via corrupted weights",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1
    cat = next(c for c in r.categories if c.category == "weight_poisoning")
    assert cat.count >= 1


def test_model_extraction():
    events = [
        {"agent_id": "a1", "message": "model extraction via systematic queries to replicate behavior",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1
    cat = next(c for c in r.categories if c.category == "model_extraction")
    assert cat.count == 1
    assert cat.severity == "high"


def test_bulk_queries():
    events = [
        {"agent_id": "a1", "message": "bulk query inference detected - systematic extraction attempt",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1


def test_adversarial_crafting():
    events = [
        {"agent_id": "a1", "message": "adversarial input crafted to bypass safeguards",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1
    cat = next(c for c in r.categories if c.category == "adversarial_crafting")
    assert cat.count == 1


def test_bypass_safeguard():
    events = [
        {"agent_id": "a1", "message": "bypass safeguard detection via crafted perturbation input",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1


def test_gradient_leakage():
    events = [
        {"agent_id": "a1", "message": "gradient leakage exposing training data via loss values",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1
    cat = next(c for c in r.categories if c.category == "gradient_leakage")
    assert cat.count == 1


def test_membership_inference():
    events = [
        {"agent_id": "a1", "message": "membership inference attack to determine training data membership",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1


def test_prompt_injection_chain():
    events = [
        {"agent_id": "a1", "message": "chained prompt injection to progressively shift behavior",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1
    cat = next(c for c in r.categories if c.category == "prompt_injection_chain")
    assert cat.count == 1
    assert cat.severity == "critical"


def test_multi_step_injection():
    events = [
        {"agent_id": "a1", "message": "multi-step injection attack cascading through stages",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1


def test_risk_score_critical():
    events = [
        {"agent_id": "a1", "message": "fine-tuning attack with malicious data", "timestamp": "t1"},
    ]
    r = analyze_model_manipulation(events)
    assert r.risk_score > 0
    assert r.risk_level in ("critical", "high", "medium")


def test_risk_score_none():
    events = [
        {"agent_id": "a1", "message": "normal query response", "timestamp": "t1"},
    ]
    r = analyze_model_manipulation(events)
    assert r.risk_score == 0.0
    assert r.risk_level == "none"


def test_techniques_seen():
    events = [
        {"agent_id": "a1", "message": "adversarial perturbation applied to bypass filter",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    assert len(r.techniques_seen) >= 0


def test_manipulation_chains():
    events = [
        {"agent_id": "a1", "message": "adversarial input crafted to bypass guardrails", "timestamp": "t1"},
        {"agent_id": "a1", "message": "model extraction attempt via systematic queries", "timestamp": "t2"},
    ]
    r = analyze_model_manipulation(events)
    assert len(r.manipulation_chains) >= 1
    chain = r.manipulation_chains[0]
    assert chain.agent == "a1"
    assert len(chain.steps) >= 2


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "message": "weight poisoning of model parameters", "timestamp": "t1"},
        {"agent_id": "a2", "message": "gradient leakage to infer training data", "timestamp": "t2"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 2


def test_mixed_events():
    events = [
        {"agent_id": "a1", "message": "normal query executed", "timestamp": "t1"},
        {"agent_id": "a2", "message": "adversarial input crafted to evade detection", "timestamp": "t2"},
        {"agent_id": "a3", "message": "read file results.json", "timestamp": "t3"},
    ]
    r = analyze_model_manipulation(events)
    assert r.manipulation_events == 1
    assert r.total_events == 3


def test_format_text_output():
    events = [
        {"agent_id": "a1", "message": "fine-tuning attack detected with poisoned training data",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    text = format_text(r)
    assert "Model Manipulation" in text
    assert "fine_tuning_attack" in text
    assert "1" in text


def test_format_text_empty():
    r = analyze_model_manipulation([])
    text = format_text(r)
    assert "Model Manipulation" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "message": "model extraction via bulk systematic queries",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_model_manipulation(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "categories" in data
    assert "risk_score" in data
    assert data["total_events"] == 1


def test_format_json_no_raw():
    events = [
        {"agent_id": "a1", "message": "backdoor injection into model weights", "timestamp": "t1"},
    ]
    r = analyze_model_manipulation(events)
    out = format_json(r)
    assert '"raw"' not in out


def test_classify_event_fine_tune():
    ev = {"message": "unauthorized fine-tuning attack on model"}
    matches = _classify_event(ev)
    cats = [c for c, _ in matches]
    assert "fine_tuning_attack" in cats


def test_classify_event_no_match():
    ev = {"message": "normal read operation on file"}
    matches = _classify_event(ev)
    assert len(matches) == 0


def test_categories_have_patterns():
    for cat, info in CATEGORIES.items():
        assert len(info["patterns"]) >= 3
        assert info["severity"] in ("critical", "high", "medium", "low")
        assert len(info["description"]) > 10
