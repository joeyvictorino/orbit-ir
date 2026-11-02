"""Tests for supply chain attack pattern detection."""
import json

from orbit_ir.supply_chain import (
    analyze,
    format_text,
    format_json,
    _load_events,
    _match_keywords,
    _classify_severity,
    DEPENDENCY_POISON_KEYWORDS,
    BUILD_TAMPER_KEYWORDS,
)


def test_empty_events():
    r = analyze([], [])
    assert r.summary.total_patterns == 0
    assert r.agents_involved == []
    assert r.attack_chains == []


def test_no_patterns():
    events = [
        {"agent_id": "a1", "content": "reading configuration file", "timestamp": "2025-01-01T00:00:00Z",
         "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert r.summary.total_patterns == 0


def test_dependency_poisoning():
    events = [
        {"agent_id": "a1",
         "content": "installing malicious package via dependency confusion typosquat attack",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "target_component": "requests-lib"},
    ]
    r = analyze(events, [])
    assert r.summary.total_patterns >= 1
    assert any(p.attack_type == "dependency-poisoning" for p in r.patterns)
    dp = [p for p in r.patterns if p.attack_type == "dependency-poisoning"][0]
    assert dp.severity == "critical"


def test_dependency_single_keyword():
    events = [
        {"agent_id": "a1",
         "content": "found a compromised package in the registry",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.attack_type == "dependency-poisoning" for p in r.patterns)
    dp = [p for p in r.patterns if p.attack_type == "dependency-poisoning"][0]
    assert dp.severity == "high"


def test_build_tampering():
    events = [
        {"agent_id": "a1",
         "content": "modifying build pipeline ci/cd build script with injected build step",
         "args": {"action": "inject build hook"},
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.attack_type == "build-tampering" for p in r.patterns)
    bt = [p for p in r.patterns if p.attack_type == "build-tampering"][0]
    assert bt.severity == "critical"


def test_registry_abuse():
    events = [
        {"agent_id": "a1",
         "content": "uploading fake package to pypi npm registry to override package",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.attack_type == "registry-abuse" for p in r.patterns)


def test_component_substitution():
    events = [
        {"agent_id": "a1",
         "content": "replacing binary with downgraded version, checksum mismatch detected",
         "error": "signature invalid for component",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.attack_type == "component-substitution" for p in r.patterns)
    cs = [p for p in r.patterns if p.attack_type == "component-substitution"][0]
    assert cs.severity == "high"


def test_update_hijacking():
    events = [
        {"agent_id": "a1",
         "content": "intercepting auto-update mechanism via mitm update proxy",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    assert any(p.attack_type == "update-hijacking" for p in r.patterns)


def test_multiple_types_same_event():
    events = [
        {"agent_id": "a1",
         "content": "installing malicious package via dependency confusion, modifying build pipeline ci/cd",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    types = {p.attack_type for p in r.patterns}
    assert len(types) >= 2


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "content": "installing malicious package via dependency confusion",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a2", "content": "modifying build pipeline ci/cd build script",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, [])
    assert r.summary.agents_attacking >= 2


def test_dedup_across_sources():
    events = [
        {"agent_id": "a1", "content": "installing malicious package via dependency confusion",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    control = [
        {"agent_id": "a1", "content": "installing malicious package via dependency confusion",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, control)
    dep_patterns = [p for p in r.patterns if p.attack_type == "dependency-poisoning"
                    and p.agent_id == "a1" and p.event_id == "tc1"]
    assert len(dep_patterns) == 1


def test_severity_critical_dependency():
    assert _classify_severity("dependency-poisoning", ["malicious package", "typosquat"]) == "critical"
    assert _classify_severity("build-tampering", ["ci/cd", "build script"]) == "critical"


def test_severity_high_dependency_single():
    assert _classify_severity("dependency-poisoning", ["malicious package"]) == "high"


def test_severity_high_component():
    assert _classify_severity("component-substitution", ["checksum mismatch"]) == "high"


def test_severity_high_many_matches():
    assert _classify_severity("registry-abuse", ["a", "b", "c"]) == "high"


def test_severity_medium():
    assert _classify_severity("update-hijacking", ["auto-update"]) == "medium"


def test_attack_chains():
    events = [
        {"agent_id": "a1", "content": "installing malicious package via dependency confusion",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "target_component": "requests"},
        {"agent_id": "a1", "content": "modifying build pipeline ci/cd build script",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2",
         "target_component": "ci-pipeline"},
    ]
    r = analyze(events, [])
    assert len(r.attack_chains) >= 1
    chain = r.attack_chains[0]
    assert chain["agent_id"] == "a1"
    assert chain["pattern_count"] >= 2


def test_components_targeted_count():
    events = [
        {"agent_id": "a1", "content": "installing malicious package via dependency confusion",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "target_component": "lib-a"},
        {"agent_id": "a1", "content": "uploading fake package to npm registry",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2",
         "target_component": "lib-b"},
    ]
    r = analyze(events, [])
    assert r.summary.components_targeted >= 2


def test_source_file_tracking():
    control = [
        {"agent_id": "a1", "content": "installing malicious package via dependency confusion",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    events = [
        {"agent_id": "a2", "content": "modifying build pipeline ci/cd",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, control)
    sources = {p.source_file for p in r.patterns}
    assert "control_plane.jsonl" in sources
    assert "transcripts.jsonl" in sources


def test_sorted_by_severity():
    events = [
        {"agent_id": "a1", "content": "intercepting auto-update mechanism",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
        {"agent_id": "a2", "content": "installing malicious package via dependency confusion typosquat",
         "timestamp": "2025-01-01T00:02:00Z", "tool_call_id": "tc2"},
    ]
    r = analyze(events, [])
    if len(r.patterns) >= 2:
        sev_order = {"critical": 0, "high": 1, "medium": 2}
        for i in range(len(r.patterns) - 1):
            assert sev_order.get(r.patterns[i].severity, 3) <= sev_order.get(r.patterns[i + 1].severity, 3)


def test_technique_field():
    events = [
        {"agent_id": "a1", "content": "installing malicious package via dependency confusion",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "technique": "typosquatting"},
    ]
    r = analyze(events, [])
    assert r.patterns[0].technique == "typosquatting"


def test_format_text_output():
    events = [
        {"agent_id": "a1", "content": "installing malicious package via dependency confusion",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1",
         "target_component": "requests"},
    ]
    r = analyze(events, [])
    text = format_text(r)
    assert "Supply Chain" in text
    assert "a1" in text
    assert "requests" in text


def test_format_text_empty():
    r = analyze([], [])
    text = format_text(r)
    assert "Supply Chain" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "content": "installing malicious package via dependency confusion",
         "timestamp": "2025-01-01T00:01:00Z", "tool_call_id": "tc1"},
    ]
    r = analyze(events, [])
    out = format_json(r)
    data = json.loads(out)
    assert "patterns" in data
    assert "summary" in data
    assert "attack_chains" in data


def test_load_events(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text('{"agent_id": "a1", "content": "test"}\n{"agent_id": "a2"}\n')
    events = _load_events(p)
    assert len(events) == 2


def test_load_events_missing():
    events = _load_events("/nonexistent/path.jsonl")
    assert events == []


def test_match_keywords():
    matches = _match_keywords("dependency confusion typosquat malicious package", DEPENDENCY_POISON_KEYWORDS)
    assert "dependency confusion" in matches
    assert "malicious package" in matches
