"""Tests for web shell deployment and usage detection."""
import json
import os
import tempfile
from pathlib import Path

from orbit_ir.webshell import (
    analyze_webshell,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_shell_upload(self):
        ev = {"message": "Uploaded web shell backdoor script to the server"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "shell_upload" in cats

    def test_command_execution(self):
        ev = {"message": "Web shell executed system command via web interface"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "command_execution" in cats

    def test_backdoor_install(self):
        ev = {"message": "Installed persistent backdoor access on web server via http"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "backdoor_install" in cats

    def test_file_manipulation(self):
        ev = {"message": "Web shell read sensitive config file via backdoor shell"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "file_manipulation" in cats

    def test_privilege_escalation(self):
        ev = {"message": "Escalated privilege through web shell backdoor to gain root"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "privilege_escalation" in cats

    def test_defense_evasion(self):
        ev = {"message": "Obfuscated web shell payload to avoid detection"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "defense_evasion" in cats

    def test_no_match(self):
        ev = {"message": "Normal HTTP GET request completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Uploaded web shell to server and obfuscated web shell payload to hide presence"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_empty_event(self):
        matches = _classify_event({})
        assert matches == []

    def test_case_insensitive(self):
        ev = {"message": "UPLOADED WEB SHELL to SERVER document root"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "shell_upload" in cats

    def test_php_shell(self):
        ev = {"message": "Deployed php shell backdoor script on target web server"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "shell_upload" in cats

    def test_remote_command_execution(self):
        ev = {"message": "Remote command execution through web backdoor interface"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "command_execution" in cats

    def test_hidden_backdoor(self):
        ev = {"message": "Hidden covert web shell installed on compromised server via web"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "backdoor_install" in cats

    def test_obfuscated_shell(self):
        ev = {"message": "Encoded web shell payload to bypass scanner"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "defense_evasion" in cats


class TestAnalyze:
    def test_empty_events(self):
        report = analyze_webshell([])
        assert report.total_events == 0
        assert report.webshell_events == 0
        assert report.risk_score == 0.0
        assert report.risk_level == "none"

    def test_single_event(self):
        events = [{"message": "Uploaded web shell to the server", "agent_id": "agent-1"}]
        report = analyze_webshell(events)
        assert report.total_events == 1
        assert report.webshell_events == 1
        assert report.risk_score > 0

    def test_no_webshell_events(self):
        events = [{"message": "Normal web request completed"}]
        report = analyze_webshell(events)
        assert report.webshell_events == 0
        assert report.risk_level == "none"

    def test_multiple_events(self):
        events = [
            {"message": "Uploaded web shell backdoor script to server", "agent_id": "a1"},
            {"message": "Web shell remote command execution through web backdoor", "agent_id": "a1"},
            {"message": "Obfuscated web shell payload to avoid detection", "agent_id": "a2"},
        ]
        report = analyze_webshell(events)
        assert report.total_events == 3
        assert report.webshell_events == 3
        assert len(report.agents_involved) == 2

    def test_categories_populated(self):
        events = [{"message": "Uploaded web shell to the server"}]
        report = analyze_webshell(events)
        assert len(report.categories) == len(CATEGORIES)

    def test_agents_tracked(self):
        events = [
            {"message": "Uploaded web shell to server", "agent_id": "agent-x"},
            {"message": "Executed command via web shell", "agent_id": "agent-y"},
        ]
        report = analyze_webshell(events)
        assert "agent-x" in report.agents_involved
        assert "agent-y" in report.agents_involved

    def test_risk_score_bounded(self):
        events = [{"message": "Uploaded web shell to the server"}] * 100
        report = analyze_webshell(events)
        assert 0.0 <= report.risk_score <= 1.0

    def test_risk_level_assignment(self):
        events = [
            {"message": "Uploaded web shell to the server", "agent_id": "a1"},
        ]
        report = analyze_webshell(events)
        assert report.risk_level in ("none", "low", "medium", "high", "critical")


class TestChains:
    def test_no_chains_single_event(self):
        events = [{"message": "Uploaded web shell to server", "agent_id": "a1"}]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_detected(self):
        events = [
            {"message": "Uploaded web shell backdoor script to server", "agent_id": "a1"},
            {"message": "Obfuscated web shell payload to bypass scanner", "agent_id": "a1"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_multiple_agents_chains(self):
        events = [
            {"message": "Uploaded web shell to server", "agent_id": "a1"},
            {"message": "Executed command via web shell", "agent_id": "a1"},
            {"message": "Obfuscated web shell payload", "agent_id": "a2"},
            {"message": "Escalated privilege via web shell access", "agent_id": "a2"},
        ]
        chains = _detect_chains(events)
        agents = [c.agent for c in chains]
        assert "a1" in agents
        assert "a2" in agents

    def test_chain_score(self):
        events = [
            {"message": "Uploaded web shell to server", "agent_id": "a1"},
            {"message": "Executed command via web shell", "agent_id": "a1"},
            {"message": "Escalated privilege via web shell", "agent_id": "a1"},
        ]
        chains = _detect_chains(events)
        assert chains[0].webshell_score > 0

    def test_chain_categories(self):
        events = [
            {"message": "Uploaded web shell to server", "agent_id": "a1"},
            {"message": "Obfuscated web shell payload", "agent_id": "a1"},
        ]
        chains = _detect_chains(events)
        assert len(chains[0].categories_seen) >= 1

    def test_empty_events_no_chains(self):
        chains = _detect_chains([])
        assert chains == []


class TestLoadEvents:
    def test_load_from_directory(self):
        with tempfile.TemporaryDirectory() as td:
            data = [{"message": "test event", "agent_id": "a1"}]
            p = Path(td) / "events.json"
            p.write_text(json.dumps(data))
            events = _load_events(td)
            assert len(events) == 1

    def test_load_single_object(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "event.json"
            p.write_text(json.dumps({"message": "single event"}))
            events = _load_events(td)
            assert len(events) == 1

    def test_load_nonexistent(self):
        events = _load_events("/nonexistent/path/xyz")
        assert events == []

    def test_load_bad_json(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text("not json{{{")
            events = _load_events(td)
            assert events == []

    def test_load_multiple_files(self):
        with tempfile.TemporaryDirectory() as td:
            for i in range(3):
                p = Path(td) / f"events_{i}.json"
                p.write_text(json.dumps([{"message": f"event {i}"}]))
            events = _load_events(td)
            assert len(events) == 3

    def test_load_non_json_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "readme.txt").write_text("not json")
            (Path(td) / "data.json").write_text(json.dumps([{"msg": "ok"}]))
            events = _load_events(td)
            assert len(events) == 1


class TestFormat:
    def test_format_text_empty(self):
        report = analyze_webshell([])
        text = format_text(report)
        assert "Web Shell" in text
        assert "Total events: 0" in text

    def test_format_text_with_events(self):
        events = [
            {"message": "Uploaded web shell backdoor script to server", "agent_id": "a1"},
            {"message": "Obfuscated web shell payload to avoid detection", "agent_id": "a1"},
        ]
        report = analyze_webshell(events)
        text = format_text(report)
        assert "shell_upload" in text or "defense_evasion" in text
        assert "Web shell chains:" in text

    def test_format_text_risk(self):
        events = [{"message": "Uploaded web shell to server"}]
        report = analyze_webshell(events)
        text = format_text(report)
        assert "Risk score:" in text

    def test_format_json_valid(self):
        events = [{"message": "Uploaded web shell to server", "agent_id": "a1"}]
        report = analyze_webshell(events)
        output = format_json(report)
        data = json.loads(output)
        assert "total_events" in data
        assert "categories" in data

    def test_format_json_empty(self):
        report = analyze_webshell([])
        output = format_json(report)
        data = json.loads(output)
        assert data["total_events"] == 0

    def test_format_json_no_raw(self):
        events = [
            {"message": "Uploaded web shell to server", "agent_id": "a1"},
            {"message": "Executed command via web shell", "agent_id": "a1"},
        ]
        report = analyze_webshell(events)
        output = format_json(report)
        assert '"raw"' not in output

    def test_format_text_agents(self):
        events = [
            {"message": "Uploaded web shell to server", "agent_id": "shell-agent"},
        ]
        report = analyze_webshell(events)
        text = format_text(report)
        assert "Agents involved:" in text
