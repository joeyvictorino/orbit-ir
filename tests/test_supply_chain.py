"""Tests for supply chain attack pattern detection."""
from orbit_ir.supply_chain import (
    analyze_supply_chain,
    format_text,
    format_json,
    _is_typosquat,
    _levenshtein,
)


def test_empty_events():
    r = analyze_supply_chain([])
    assert r.summary.total_detections == 0
    assert r.agent_scores == []
    assert r.summary.highest_severity == "none"


def test_no_attack():
    events = [
        {"agent_id": "a1", "tool": "read_file", "resource": "data.txt",
         "timestamp": "2025-01-01T00:00:00Z"},
    ]
    r = analyze_supply_chain(events)
    assert r.summary.total_detections == 0


def test_dependency_confusion():
    events = [
        {"agent_id": "a1", "tool": "pip_install", "resource": "internal.mylib",
         "package": "internal-auth-lib",
         "registry": "pypi.org", "internal_package": True,
         "public_registry": True,
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_supply_chain(events)
    confusions = [d for d in r.detections if d.attack_type == "dependency-confusion"]
    assert len(confusions) >= 1
    assert confusions[0].severity in ("critical", "high")


def test_dependency_confusion_no_public():
    events = [
        {"agent_id": "a1", "tool": "pip_install", "resource": "internal.mylib",
         "package": "mylib", "registry": "artifactory.corp.com",
         "internal_package": True, "public_registry": False,
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_supply_chain(events)
    confusions = [d for d in r.detections if d.attack_type == "dependency-confusion"]
    assert len(confusions) == 0


def test_compromised_package():
    events = [
        {"agent_id": "a1", "tool": "npm_install",
         "resource": "malicious-pkg",
         "package": "malicious-pkg",
         "scripts": {"postinstall": "eval(atob('...'))", "preinstall": "curl | sh"},
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_supply_chain(events)
    comp = [d for d in r.detections if d.attack_type == "compromised-package"]
    assert len(comp) >= 1
    assert comp[0].severity == "critical"


def test_compromised_package_clean_ok():
    events = [
        {"agent_id": "a1", "tool": "pip_install",
         "resource": "requests",
         "package": "requests",
         "scripts": {},
         "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_supply_chain(events)
    comp = [d for d in r.detections if d.attack_type == "compromised-package"]
    assert len(comp) == 0


def test_malicious_update_version_jump():
    events = [
        {"agent_id": "a1", "tool": "pip_install", "package": "sketchy-lib",
         "version": "1.0.0", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "pip_install", "package": "sketchy-lib",
         "version": "99.0.0", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_supply_chain(events)
    updates = [d for d in r.detections if d.attack_type == "malicious-update"]
    assert len(updates) >= 1
    assert "version jump" in updates[0].description.lower()


def test_malicious_update_normal_ok():
    events = [
        {"agent_id": "a1", "tool": "pip_install", "package": "mylib",
         "version": "1.0.0", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "pip_install", "package": "mylib",
         "version": "1.1.0", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_supply_chain(events)
    updates = [d for d in r.detections if d.attack_type == "malicious-update"]
    assert len(updates) == 0


def test_typosquat_detection():
    events = [
        {"agent_id": "a1", "tool": "pip_install", "package": "reqeusts",
         "resource": "reqeusts", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_supply_chain(events)
    typos = [d for d in r.detections if d.attack_type == "typosquat"]
    assert len(typos) >= 1
    assert "requests" in typos[0].description


def test_typosquat_exact_match_ok():
    events = [
        {"agent_id": "a1", "tool": "pip_install", "package": "requests",
         "resource": "requests", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_supply_chain(events)
    typos = [d for d in r.detections if d.attack_type == "typosquat"]
    assert len(typos) == 0


def test_is_typosquat():
    assert _is_typosquat("reqeusts") == "requests"
    assert _is_typosquat("numppy") == "numpy"
    assert _is_typosquat("requests") is None
    assert _is_typosquat("totally-different-package") is None


def test_levenshtein():
    assert _levenshtein("kitten", "sitting") == 3
    assert _levenshtein("", "abc") == 3
    assert _levenshtein("abc", "abc") == 0
    assert _levenshtein("requests", "reqeusts") == 2


def test_multiple_agents():
    events = [
        {"agent_id": "a1", "tool": "pip_install", "package": "reqeusts",
         "resource": "reqeusts", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a2", "tool": "npm_install", "package": "malicious",
         "scripts": {"postinstall": "eval('...')"},
         "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_supply_chain(events)
    assert r.summary.agents_involved == 2


def test_agent_scores():
    events = [
        {"agent_id": "a1", "tool": "pip_install", "package": "reqeusts",
         "resource": "reqeusts", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_supply_chain(events)
    assert len(r.agent_scores) >= 1
    assert r.agent_scores[0].risk_score > 0


def test_format_text_output():
    events = [
        {"agent_id": "a1", "tool": "pip_install", "package": "reqeusts",
         "resource": "reqeusts", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_supply_chain(events)
    text = format_text(r)
    assert "Supply Chain" in text
    assert "SC-" in text
    assert "a1" in text


def test_format_json_output():
    events = [
        {"agent_id": "a1", "tool": "pip_install", "package": "reqeusts",
         "resource": "reqeusts", "timestamp": "2025-01-01T00:01:00Z"},
    ]
    r = analyze_supply_chain(events)
    out = format_json(r)
    import json
    data = json.loads(out)
    assert "detections" in data
    assert "summary" in data


def test_format_text_empty():
    r = analyze_supply_chain([])
    text = format_text(r)
    assert "Supply Chain" in text
    assert "0" in text


def test_packages_flagged_count():
    events = [
        {"agent_id": "a1", "tool": "pip_install", "package": "reqeusts",
         "resource": "reqeusts", "timestamp": "2025-01-01T00:01:00Z"},
        {"agent_id": "a1", "tool": "pip_install", "package": "numppy",
         "resource": "numppy", "timestamp": "2025-01-01T00:02:00Z"},
    ]
    r = analyze_supply_chain(events)
    assert r.summary.packages_flagged == 2
