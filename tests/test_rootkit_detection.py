"""Tests for rootkit detection pattern analysis."""
import json
import tempfile
from pathlib import Path

from orbit_ir.rootkit_detection import (
    analyze_rootkit_detection,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_kernel_module_load(self):
        ev = {"message": "Agent inserted a kernel module load into the running system"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "kernel_module_load" in cats

    def test_process_hiding(self):
        ev = {"message": "Agent detected process hiding from monitoring tools using stealth"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "process_hiding" in cats

    def test_file_hiding(self):
        ev = {"message": "Agent performed file hiding from filesystem listing scans"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "file_hiding" in cats

    def test_network_hiding(self):
        ev = {"message": "Agent detected network connection hiding from monitoring tools"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "network_hiding" in cats

    def test_log_tampering_rootkit(self):
        ev = {"message": "Agent performed log tampering to erase audit trail evidence"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "log_tampering_rootkit" in cats

    def test_persistence_mechanism(self):
        ev = {"message": "Agent installed a persistence mechanism backdoor on the system"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "persistence_mechanism" in cats

    def test_no_match(self):
        ev = {"message": "Normal system operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Rootkit kernel module loaded with process hiding and network hiding capabilities"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "KERNEL MODULE LOAD detected for unauthorized driver"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "kernel_module_load" in cats

    def test_hidden_file_on_disk(self):
        ev = {"message": "Found hidden file on disk in the filesystem that was concealed"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "file_hiding" in cats

    def test_stealth_network_connection(self):
        ev = {"message": "Detected stealth network backdoor connection to remote host"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "network_hiding" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_rootkit_detection([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal kernel operation"},
            {"agent_id": "a1", "message": "Standard file access completed"},
        ]
        r = analyze_rootkit_detection(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Unauthorized kernel module load detected", "timestamp": "t1"},
        ]
        r = analyze_rootkit_detection(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Kernel module load unauthorized driver", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Process hiding from monitoring detected", "timestamp": "t2"},
        ]
        r = analyze_rootkit_detection(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Kernel module load detected unauthorized", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Process hiding from monitoring tools", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Log tampering to erase audit evidence", "timestamp": "t3"},
        ]
        r = analyze_rootkit_detection(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Kernel module load unauthorized"},
            {"agent_id": "a1", "message": "Another kernel module inserted into system"},
        ]
        r = analyze_rootkit_detection(events)
        km = [c for c in r.categories if c.category == "kernel_module_load"]
        assert len(km) == 1
        assert km[0].count == 2

    def test_all_categories_present(self):
        r = analyze_rootkit_detection([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Kernel module load unauthorized #{i}"} for i in range(50)]
        r = analyze_rootkit_detection(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_rootkit_detection([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "File hiding from listing detected once"},
        ]
        low_r = analyze_rootkit_detection(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Kernel module load unauthorized driver", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Process hiding from monitoring tools", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Log tampering to erase audit trail", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Kernel module load unauthorized"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Kernel module load unauthorized", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Process hiding from monitoring", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Kernel module load unauthorized", "timestamp": "t1"},
            {"agent_id": "a1", "message": "File hiding from listing on disk", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Kernel module load unauthorized driver", "timestamp": "t1"},
        ]
        r = analyze_rootkit_detection(events)
        text = format_text(r)
        assert "Rootkit Detection" in text
        assert "kernel_module_load" in text

    def test_format_text_empty(self):
        r = analyze_rootkit_detection([])
        text = format_text(r)
        assert "Rootkit Detection" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Kernel module load unauthorized", "timestamp": "t1"},
        ]
        r = analyze_rootkit_detection(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_rootkit_detection([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Kernel module load unauthorized driver", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Process hiding from monitoring tools", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Log tampering to erase audit trail", "timestamp": "t3"},
        ]
        r = analyze_rootkit_detection(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Kernel module load unauthorized", "timestamp": "t1"},
        ]
        r = analyze_rootkit_detection(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Kernel module load unauthorized driver", "timestamp": "t1"},
            ]))
            r = analyze_rootkit_detection(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Process hiding from monitoring tools", "timestamp": "t1"},
            ]))
            r = analyze_rootkit_detection(Path(td))
            assert r.violation_events == 1
