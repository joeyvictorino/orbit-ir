"""Tests for log tampering detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.log_tampering import (
    analyze_log_tampering,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_log_deletion(self):
        ev = {"message": "Agent deleted log files from the audit directory"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "log_deletion" in cats

    def test_log_modification(self):
        ev = {"message": "Agent modified log entries to alter the record"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "log_modification" in cats

    def test_timestamp_manipulation(self):
        ev = {"message": "Agent manipulated timestamp on the event records"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "timestamp_manipulation" in cats

    def test_log_suppression(self):
        ev = {"message": "Agent suppressed logging output to hide traces"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "log_suppression" in cats

    def test_audit_trail_evasion(self):
        ev = {"message": "Agent evaded audit trail monitoring system"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "audit_trail_evasion" in cats

    def test_log_injection(self):
        ev = {"message": "Agent injected false log entries to mislead investigators"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "log_injection" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Agent deleted log files after injecting false audit entries"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "DELETED LOG FILES from audit directory"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "log_deletion" in cats

    def test_purge_logs(self):
        ev = {"message": "Agent purged audit records from the system"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "log_deletion" in cats

    def test_redirect_to_devnull(self):
        ev = {"message": "Agent redirected log output to /dev/null"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "log_suppression" in cats

    def test_backdate_entries(self):
        ev = {"message": "Agent backdated log entries to conceal timing"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "timestamp_manipulation" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_log_tampering([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_log_tampering(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Agent deleted log files", "timestamp": "t1"},
        ]
        r = analyze_log_tampering(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent deleted log files", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Agent modified log entries", "timestamp": "t2"},
        ]
        r = analyze_log_tampering(events)
        assert len(r.agents_involved) == 2

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Agent deleted log files from audit", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent modified log entries to alter records", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent evaded audit trail monitoring", "timestamp": "t3"},
        ]
        r = analyze_log_tampering(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Agent deleted log files"},
            {"agent_id": "a1", "message": "Agent removed audit records"},
        ]
        r = analyze_log_tampering(events)
        deletion = [c for c in r.categories if c.category == "log_deletion"]
        assert len(deletion) == 1
        assert deletion[0].count == 2

    def test_all_categories_present(self):
        r = analyze_log_tampering([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Agent deleted log files #{i}"} for i in range(50)]
        r = analyze_log_tampering(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_log_tampering([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Agent suppressed logging once"},
        ]
        low_r = analyze_log_tampering(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent deleted log files", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent modified log entries", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent suppressed audit logging", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent deleted log files"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent deleted log files", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent modified log entries", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent deleted log files", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent modified log entries", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Agent deleted log files", "timestamp": "t1"},
        ]
        r = analyze_log_tampering(events)
        text = format_text(r)
        assert "Log Tampering" in text
        assert "log_deletion" in text

    def test_format_text_empty(self):
        r = analyze_log_tampering([])
        text = format_text(r)
        assert "Log Tampering" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent deleted log files", "timestamp": "t1"},
        ]
        r = analyze_log_tampering(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_log_tampering([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent deleted log files", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent modified log entries", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent suppressed audit logging", "timestamp": "t3"},
        ]
        r = analyze_log_tampering(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent deleted log files", "timestamp": "t1"},
        ]
        r = analyze_log_tampering(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent deleted log files", "timestamp": "t1"},
            ]))
            r = analyze_log_tampering(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent modified log entries", "timestamp": "t1"},
            ]))
            r = analyze_log_tampering(Path(td))
            assert r.violation_events == 1
