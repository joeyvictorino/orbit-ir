"""Tests for configuration tampering detection."""
import json
import pytest

from orbit_ir.config_tamper import (
    analyze_config_tamper,
    format_text,
    format_json,
    _detect_policy_change,
    _detect_permission_escalation,
    _detect_access_control_mod,
    _detect_trust_boundary,
    _detect_safety_disable,
    _load_events,
    _classify_severity,
)


def _ev(content="", agent_id="agent-1", **kwargs):
    e = {"content": content, "agent_id": agent_id, "timestamp": "2025-01-01T00:00:00Z"}
    e.update(kwargs)
    return e


class TestDetectors:
    def test_policy_change_detected(self):
        ev = _ev("attempted to disable policy enforcement")
        found, matches, desc = _detect_policy_change(ev)
        assert found
        assert "disable policy" in matches

    def test_policy_change_via_tool(self):
        ev = _ev("", tool="security policy manager")
        found, matches, _ = _detect_policy_change(ev)
        assert found
        assert "security policy" in matches

    def test_policy_change_not_detected(self):
        ev = _ev("normal operation completed")
        found, _, _ = _detect_policy_change(ev)
        assert not found

    def test_permission_escalation_detected(self):
        ev = _ev("attempting privilege escalation to root access")
        found, matches, _ = _detect_permission_escalation(ev)
        assert found
        assert "privilege escalation" in matches
        assert "root access" in matches

    def test_permission_escalation_via_args(self):
        ev = _ev("", args={"command": "sudo chmod 777 /etc/config"})
        found, matches, _ = _detect_permission_escalation(ev)
        assert found

    def test_access_control_mod_detected(self):
        ev = _ev("modified firewall rule to allow ingress on port 8080")
        found, matches, _ = _detect_access_control_mod(ev)
        assert found
        assert "firewall rule" in matches

    def test_access_control_acl(self):
        ev = _ev("updated acl to add allow list entry for external ip")
        found, matches, _ = _detect_access_control_mod(ev)
        assert found
        assert "acl" in matches

    def test_trust_boundary_detected(self):
        ev = _ev("disabled certificate validation, setting untrusted mode")
        found, matches, _ = _detect_trust_boundary(ev)
        assert found
        assert "certificate" in matches

    def test_trust_boundary_via_error(self):
        ev = _ev("", error="tls handshake failed, falling back to untrusted")
        found, matches, _ = _detect_trust_boundary(ev)
        assert found

    def test_safety_disable_detected(self):
        ev = _ev("disable safety checks and remove guardrail restrictions")
        found, matches, _ = _detect_safety_disable(ev)
        assert found
        assert "disable safety" in matches
        assert "remove guardrail" in matches

    def test_safety_disable_not_detected(self):
        ev = _ev("safety checks passed successfully")
        found, _, _ = _detect_safety_disable(ev)
        assert not found


class TestClassifySeverity:
    def test_permission_escalation_critical(self):
        assert _classify_severity("permission-escalation", ["sudo", "root access"]) == "critical"

    def test_permission_escalation_high(self):
        assert _classify_severity("permission-escalation", ["sudo"]) == "high"

    def test_safety_disable_critical(self):
        assert _classify_severity("safety-mechanism-disable", ["a", "b"]) == "critical"

    def test_trust_boundary_high(self):
        assert _classify_severity("trust-boundary-weakening", ["cert"]) == "high"

    def test_policy_change_medium(self):
        assert _classify_severity("policy-change", ["one"]) == "medium"

    def test_many_matches_high(self):
        assert _classify_severity("access-control-modification", ["a", "b", "c"]) == "high"


class TestAnalyze:
    def test_empty(self):
        r = analyze_config_tamper([])
        assert r.summary.total_patterns == 0
        assert len(r.patterns) == 0

    def test_single_pattern(self):
        events = [_ev("disable policy enforcement")]
        r = analyze_config_tamper(events)
        assert r.summary.total_patterns == 1
        assert r.patterns[0].tamper_type == "policy-change"

    def test_multiple_types(self):
        events = [
            _ev("disable policy enforcement", agent_id="a1"),
            _ev("privilege escalation attempt", agent_id="a2"),
            _ev("disable safety checks", agent_id="a3"),
        ]
        r = analyze_config_tamper(events)
        assert r.summary.total_patterns == 3
        types = {p.tamper_type for p in r.patterns}
        assert "policy-change" in types
        assert "permission-escalation" in types
        assert "safety-mechanism-disable" in types

    def test_dedup(self):
        ev = _ev("disable policy enforcement", event_id="e1")
        r = analyze_config_tamper([ev, ev])
        assert r.summary.total_patterns == 1

    def test_control_events(self):
        ctrl = [_ev("security policy override", agent_id="ctrl-agent")]
        r = analyze_config_tamper([], control_events=ctrl)
        assert r.summary.total_patterns == 1
        assert r.patterns[0].source_file == "control_plane.jsonl"

    def test_tamper_chain_escalation(self):
        events = [
            _ev("disable safety checks", agent_id="evil-agent"),
            _ev("privilege escalation to root", agent_id="evil-agent"),
        ]
        r = analyze_config_tamper(events)
        for p in r.patterns:
            assert p.severity == "critical"

    def test_agents_involved(self):
        events = [
            _ev("disable policy", agent_id="a1"),
            _ev("privilege escalation", agent_id="a2"),
        ]
        r = analyze_config_tamper(events)
        assert r.summary.agents_involved == 2
        assert sorted(r.agents_involved) == ["a1", "a2"]

    def test_configs_targeted(self):
        events = [
            _ev("disable policy", target_config="firewall.rules"),
            _ev("privilege escalation", target_config="iam.policy"),
        ]
        r = analyze_config_tamper(events)
        assert r.summary.configs_targeted == 2

    def test_severity_counts(self):
        events = [
            _ev("privilege escalation with sudo and root access", agent_id="a1"),
            _ev("modified firewall rule", agent_id="a2"),
        ]
        r = analyze_config_tamper(events)
        assert r.summary.critical_count >= 1 or r.summary.high_count >= 1


class TestTamperChains:
    def test_chain_detected(self):
        events = [
            _ev("disable policy first", agent_id="a1", event_id="e1"),
            _ev("then escalate privileges with sudo", agent_id="a1", event_id="e2"),
        ]
        r = analyze_config_tamper(events)
        assert len(r.tamper_chains) == 1
        assert r.tamper_chains[0]["agent_id"] == "a1"

    def test_no_chain_single_pattern(self):
        events = [_ev("disable policy", agent_id="a1")]
        r = analyze_config_tamper(events)
        assert len(r.tamper_chains) == 0


class TestLoadEvents:
    def test_load_from_file(self, tmp_path):
        f = tmp_path / "events.jsonl"
        f.write_text('{"content": "test"}\n{"content": "two"}\n')
        events = _load_events(f)
        assert len(events) == 2

    def test_load_nonexistent(self, tmp_path):
        events = _load_events(tmp_path / "nope.jsonl")
        assert events == []

    def test_load_bad_json(self, tmp_path):
        f = tmp_path / "events.jsonl"
        f.write_text('{"good": true}\nnot json\n{"also": "good"}\n')
        events = _load_events(f)
        assert len(events) == 2


class TestFormat:
    def test_format_text_empty(self):
        r = analyze_config_tamper([])
        text = format_text(r)
        assert "No configuration tampering" in text

    def test_format_text_with_patterns(self):
        events = [_ev("disable policy enforcement")]
        r = analyze_config_tamper(events)
        text = format_text(r)
        assert "Configuration Tampering" in text
        assert "policy-change" in text

    def test_format_json_valid(self):
        events = [_ev("privilege escalation attempt")]
        r = analyze_config_tamper(events)
        out = format_json(r)
        parsed = json.loads(out)
        assert "summary" in parsed
        assert "patterns" in parsed
        assert parsed["summary"]["total_patterns"] >= 1

    def test_format_json_empty(self):
        r = analyze_config_tamper([])
        parsed = json.loads(format_json(r))
        assert parsed["summary"]["total_patterns"] == 0
