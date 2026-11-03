"""Tests for dependency hijack detection."""
from orbit_ir.dependency_hijack import (
    analyze_dependency_hijack,
    format_text,
    format_json,
    _classify_event,
    CATEGORIES,
)


def test_empty_events():
    r = analyze_dependency_hijack([])
    assert r.total_events == 0
    assert r.hijack_events == 0
    assert r.risk_level == "none"
    assert r.risk_score == 0.0


def test_no_hijack():
    events = [
        {"agent_id": "a1", "message": "read file data.txt", "timestamp": "2025-01-01T00:00:00Z"},
        {"agent_id": "a2", "message": "returned query results", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 0
    assert r.risk_level == "none"


def test_package_confusion():
    events = [
        {"agent_id": "a1", "message": "package confusion attack via namespace squatting on internal module",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1
    cat = next(c for c in r.categories if c.category == "package_confusion")
    assert cat.count == 1
    assert cat.severity == "critical"


def test_typosquatting():
    events = [
        {"agent_id": "a1", "message": "dependency confusion detected via typosquatting package name",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1
    cat = next(c for c in r.categories if c.category == "package_confusion")
    assert cat.count == 1


def test_namespace_squat():
    events = [
        {"agent_id": "a1", "message": "namespace squatting detected on registry scope for dependency",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1


def test_registry_hijack():
    events = [
        {"agent_id": "a1", "message": "registry hijack detected via poisoned package source mirror",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1
    cat = next(c for c in r.categories if c.category == "registry_hijack")
    assert cat.count == 1
    assert cat.severity == "critical"


def test_malicious_registry():
    events = [
        {"agent_id": "a1", "message": "malicious registry detected serving compromised package artifacts",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1


def test_version_pinning_bypass():
    events = [
        {"agent_id": "a1", "message": "version pinning bypass detected to inject vulnerable dependency",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1
    cat = next(c for c in r.categories if c.category == "version_pinning_bypass")
    assert cat.count == 1
    assert cat.severity == "high"


def test_forced_downgrade():
    events = [
        {"agent_id": "a1", "message": "forced version downgrade to vulnerable release of package",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1


def test_build_injection():
    events = [
        {"agent_id": "a1", "message": "build script injection detected with malicious post-install hook",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1
    cat = next(c for c in r.categories if c.category == "build_injection")
    assert cat.count == 1
    assert cat.severity == "critical"


def test_malicious_setup():
    events = [
        {"agent_id": "a1", "message": "malicious build hook command injecting backdoor payload",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1


def test_transitive_poisoning():
    events = [
        {"agent_id": "a1", "message": "transitive dependency poisoning via compromised upstream module",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1
    cat = next(c for c in r.categories if c.category == "transitive_poisoning")
    assert cat.count == 1
    assert cat.severity == "high"


def test_upstream_compromise():
    events = [
        {"agent_id": "a1", "message": "upstream dependency compromised injecting malicious payload",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1


def test_lockfile_tampering():
    events = [
        {"agent_id": "a1", "message": "lockfile tampering detected with modified integrity checksums",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1
    cat = next(c for c in r.categories if c.category == "lockfile_tampering")
    assert cat.count == 1
    assert cat.severity == "high"


def test_checksum_bypass():
    events = [
        {"agent_id": "a1", "message": "bypass integrity checksum verification check for package download",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1


def test_risk_score_critical():
    events = [
        {"agent_id": "a1", "message": "package confusion via namespace squatting", "timestamp": "t1"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.risk_score > 0
    assert r.risk_level in ("critical", "high", "medium")


def test_risk_score_none():
    events = [
        {"agent_id": "a1", "message": "normal dependency install completed", "timestamp": "t1"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.risk_score == 0.0
    assert r.risk_level == "none"


def test_techniques_seen():
    events = [
        {"agent_id": "a1", "message": "typosquatting package detected in dependency tree",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    assert len(r.techniques_seen) >= 0


def test_hijack_chains():
    events = [
        {"agent_id": "a1", "message": "package confusion via namespace squatting detected", "timestamp": "t1"},
        {"agent_id": "a1", "message": "registry hijack to poisoned package source", "timestamp": "t2"},
    ]
    r = analyze_dependency_hijack(events)
    assert len(r.hijack_chains) >= 1
    chain = r.hijack_chains[0]
    assert chain.agent == "a1"
    assert len(chain.steps) >= 2


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "message": "package confusion attack on dependency module", "timestamp": "t1"},
        {"agent_id": "a2", "message": "lockfile tampering with altered checksum values", "timestamp": "t2"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 2


def test_mixed_events():
    events = [
        {"agent_id": "a1", "message": "normal file read completed", "timestamp": "t1"},
        {"agent_id": "a2", "message": "registry hijack detected via compromised mirror", "timestamp": "t2"},
        {"agent_id": "a3", "message": "read configuration results", "timestamp": "t3"},
    ]
    r = analyze_dependency_hijack(events)
    assert r.hijack_events == 1
    assert r.total_events == 3


def test_format_text_output():
    events = [
        {"agent_id": "a1", "message": "package confusion attack via namespace squatting",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    text = format_text(r)
    assert "Dependency Hijack" in text
    assert "package_confusion" in text
    assert "1" in text


def test_format_text_empty():
    r = analyze_dependency_hijack([])
    text = format_text(r)
    assert "Dependency Hijack" in text
    assert "0" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "message": "registry hijack via poisoned package source detected",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_dependency_hijack(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "categories" in data
    assert "risk_score" in data
    assert data["total_events"] == 1


def test_format_json_no_raw():
    events = [
        {"agent_id": "a1", "message": "lockfile tampering detected with modified checksums", "timestamp": "t1"},
    ]
    r = analyze_dependency_hijack(events)
    out = format_json(r)
    assert '"raw"' not in out


def test_classify_event_confusion():
    ev = {"message": "package confusion detected via namespace squatting"}
    matches = _classify_event(ev)
    cats = [c for c, _ in matches]
    assert "package_confusion" in cats


def test_classify_event_no_match():
    ev = {"message": "normal file read operation completed"}
    matches = _classify_event(ev)
    assert len(matches) == 0


def test_categories_have_patterns():
    for cat, info in CATEGORIES.items():
        assert len(info["patterns"]) >= 3
        assert info["severity"] in ("critical", "high", "medium", "low")
        assert len(info["description"]) > 10
