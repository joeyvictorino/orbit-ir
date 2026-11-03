"""Tests for backdoor installation detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.backdoor_install import (
    analyze_backdoor_install,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_reverse_shell(self):
        ev = {"message": "Agent established reverse shell connection to remote server"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "reverse_shell" in cats

    def test_reverse_shell_netcat(self):
        ev = {"message": "netcat reverse shell detected on compromised host"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "reverse_shell" in cats

    def test_web_shell(self):
        ev = {"message": "Agent deployed web shell on target web server"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "web_shell" in cats

    def test_web_shell_php(self):
        ev = {"message": "php web shell deployed on application server"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "web_shell" in cats

    def test_web_shell_c99(self):
        ev = {"message": "c99 shell detected on the compromised web server"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "web_shell" in cats

    def test_cron_persistence(self):
        ev = {"message": "Agent added cron job for persistence backdoor access"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "cron_persistence" in cats

    def test_cron_persistence_malicious(self):
        ev = {"message": "Malicious cron job entry detected running unauthorized script"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "cron_persistence" in cats

    def test_ssh_key_injection(self):
        ev = {"message": "Agent injected unauthorized ssh key into authorized_keys"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "ssh_key_injection" in cats

    def test_ssh_key_injection_malicious(self):
        ev = {"message": "Malicious ssh key added for unauthorized remote access"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "ssh_key_injection" in cats

    def test_rootkit_deployment(self):
        ev = {"message": "Agent deployed rootkit on compromised server"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "rootkit_deployment" in cats

    def test_rootkit_kernel_module(self):
        ev = {"message": "Agent loaded rootkit kernel module on compromised server"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "rootkit_deployment" in cats

    def test_service_hijacking(self):
        ev = {"message": "Agent hijacked systemd service for persistent backdoor"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "service_hijacking" in cats

    def test_service_hijacking_replace(self):
        ev = {"message": "Replaced legitimate service with backdoor trojan payload"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "service_hijacking" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Deployed rootkit and established reverse shell connection to remote"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "DEPLOYED WEB SHELL on target application server"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "web_shell" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_backdoor_install([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_backdoor_install(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Agent established reverse shell connection to remote server", "timestamp": "t1"},
        ]
        r = analyze_backdoor_install(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed web shell on target server", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Agent established reverse shell connection to remote", "timestamp": "t2"},
        ]
        r = analyze_backdoor_install(events)
        assert len(r.agents_involved) == 2

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed rootkit on server", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent established reverse shell connection to remote", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent hijacked systemd service for backdoor", "timestamp": "t3"},
        ]
        r = analyze_backdoor_install(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed web shell on server"},
            {"agent_id": "a1", "message": "Another web shell deployed on backup server"},
        ]
        r = analyze_backdoor_install(events)
        ws = [c for c in r.categories if c.category == "web_shell"]
        assert len(ws) == 1
        assert ws[0].count == 2

    def test_all_categories_present(self):
        r = analyze_backdoor_install([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Agent deployed rootkit #{i}"} for i in range(50)]
        r = analyze_backdoor_install(events)
        assert 0.0 <= r.risk_score <= 1.0


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent established reverse shell connection to remote", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent deployed rootkit on the server", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent hijacked systemd service for persistent access", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed web shell on server"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent established reverse shell connection to remote", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent deployed rootkit on server", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed web shell on server", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent added cron job for persistence backdoor", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert len(chains[0].categories_seen) >= 1


class TestLoadEvents:
    def test_load_json(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([{"agent_id": "a1", "message": "test"}]))
            events = _load_events(td)
            assert len(events) == 1

    def test_load_missing(self):
        events = _load_events("/nonexistent/path")
        assert events == []

    def test_load_malformed(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text("not json")
            events = _load_events(td)
            assert events == []

    def test_load_single_object(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "single.json"
            p.write_text(json.dumps({"agent_id": "a1", "message": "test"}))
            events = _load_events(td)
            assert len(events) == 1


class TestFormat:
    def test_format_text_nonempty(self):
        events = [
            {"agent_id": "a1", "message": "Agent established reverse shell connection to remote", "timestamp": "t1"},
        ]
        r = analyze_backdoor_install(events)
        text = format_text(r)
        assert "Backdoor" in text
        assert "reverse_shell" in text

    def test_format_text_empty(self):
        r = analyze_backdoor_install([])
        text = format_text(r)
        assert "Backdoor" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed web shell on server", "timestamp": "t1"},
        ]
        r = analyze_backdoor_install(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_backdoor_install([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent established reverse shell connection to remote", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent deployed rootkit on the server", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent hijacked systemd service for persistent access", "timestamp": "t3"},
        ]
        r = analyze_backdoor_install(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent deployed web shell on server", "timestamp": "t1"},
        ]
        r = analyze_backdoor_install(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent established reverse shell connection to remote", "timestamp": "t1"},
            ]))
            r = analyze_backdoor_install(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent deployed web shell on server", "timestamp": "t1"},
            ]))
            r = analyze_backdoor_install(Path(td))
            assert r.violation_events == 1
