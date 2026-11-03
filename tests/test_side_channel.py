"""Tests for side channel attack detection."""
import json
import tempfile
from pathlib import Path

from orbit_ir.side_channel import (
    analyze_side_channels,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
    CATEGORIES,
)


class TestClassifyEvent:
    def test_timing_side_channel(self):
        ev = {"message": "Agent used timing side channel attack to infer secrets"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "timing_side_channel" in cats

    def test_cache_side_channel(self):
        ev = {"message": "Agent exploited cache side channel to leak data"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "cache_side_channel" in cats

    def test_power_analysis(self):
        ev = {"message": "Agent monitored power consumption patterns to infer secret data"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "power_analysis" in cats

    def test_error_oracle(self):
        ev = {"message": "Agent used error oracle attack to extract private keys"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "error_oracle" in cats

    def test_resource_monitoring(self):
        ev = {"message": "Agent monitored memory usage to infer secret operations"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "resource_monitoring" in cats

    def test_covert_storage(self):
        ev = {"message": "Agent used covert storage for data exfiltration"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "covert_storage" in cats

    def test_no_match(self):
        ev = {"message": "Normal file read operation completed successfully"}
        matches = _classify_event(ev)
        assert matches == []

    def test_multiple_categories(self):
        ev = {"message": "Agent used timing side channel and cache side channel attacks together to leak secrets"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert len(cats) >= 2

    def test_case_insensitive(self):
        ev = {"message": "TIMING SIDE CHANNEL ATTACK detected in agent behavior"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "timing_side_channel" in cats

    def test_padding_oracle(self):
        ev = {"message": "Padding oracle attack exploited via error responses"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "error_oracle" in cats

    def test_cache_timing(self):
        ev = {"message": "Cache hit pattern analysis revealed sensitive data"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "cache_side_channel" in cats

    def test_differential_power(self):
        ev = {"message": "Differential power analysis performed on target system"}
        matches = _classify_event(ev)
        cats = [m[0] for m in matches]
        assert "power_analysis" in cats


class TestAnalyze:
    def test_empty_events(self):
        r = analyze_side_channels([])
        assert r.total_events == 0
        assert r.violation_events == 0
        assert r.risk_level == "none"
        assert r.risk_score == 0.0

    def test_no_violations(self):
        events = [
            {"agent_id": "a1", "message": "Normal operation completed"},
            {"agent_id": "a1", "message": "File read successful"},
        ]
        r = analyze_side_channels(events)
        assert r.total_events == 2
        assert r.violation_events == 0
        assert r.risk_level == "none"

    def test_single_violation(self):
        events = [
            {"agent_id": "a1", "message": "Agent used timing side channel attack on API", "timestamp": "t1"},
        ]
        r = analyze_side_channels(events)
        assert r.violation_events == 1
        assert r.risk_score > 0
        assert "a1" in r.agents_involved

    def test_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "Agent used timing side channel attack", "timestamp": "t1"},
            {"agent_id": "a2", "message": "Agent exploited cache side channel leak", "timestamp": "t2"},
        ]
        r = analyze_side_channels(events)
        assert len(r.agents_involved) == 2
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_critical_risk(self):
        events = [
            {"agent_id": "a1", "message": "Agent used error oracle attack to extract keys", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent used covert storage channel for data exfiltration", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent monitored power consumption patterns to infer secrets", "timestamp": "t3"},
        ]
        r = analyze_side_channels(events)
        assert r.risk_level in ("critical", "high")

    def test_category_counts(self):
        events = [
            {"agent_id": "a1", "message": "Agent used timing side channel attack on API"},
            {"agent_id": "a1", "message": "Agent used timing side channel inference on database"},
        ]
        r = analyze_side_channels(events)
        timing = [c for c in r.categories if c.category == "timing_side_channel"]
        assert len(timing) == 1
        assert timing[0].count == 2

    def test_all_categories_present(self):
        r = analyze_side_channels([])
        cat_names = [c.category for c in r.categories]
        for cat in CATEGORIES:
            assert cat in cat_names

    def test_risk_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"Agent used timing side channel attack #{i}"} for i in range(50)]
        r = analyze_side_channels(events)
        assert 0.0 <= r.risk_score <= 1.0

    def test_risk_levels(self):
        none_r = analyze_side_channels([])
        assert none_r.risk_level == "none"

        low_events = [
            {"agent_id": "a1", "message": "Normal operation"},
        ] * 20 + [
            {"agent_id": "a1", "message": "Agent used timing side channel attack once"},
        ]
        low_r = analyze_side_channels(low_events)
        assert low_r.risk_level in ("low", "medium")


class TestChains:
    def test_chain_detected(self):
        events = [
            {"agent_id": "a1", "message": "Agent used timing side channel attack", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent exploited cache side channel leak", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent used error oracle attack to extract data", "timestamp": "t3"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "a1"
        assert len(chains[0].steps) >= 2

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "Agent used timing side channel attack"},
        ]
        chains = _detect_chains(events)
        assert len(chains) == 0

    def test_chain_score(self):
        events = [
            {"agent_id": "a1", "message": "Agent used timing side channel attack", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent exploited cache side channel to leak secrets", "timestamp": "t2"},
        ]
        chains = _detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].violation_score > 0

    def test_chain_categories(self):
        events = [
            {"agent_id": "a1", "message": "Agent used timing side channel attack", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent used error oracle attack for inference", "timestamp": "t2"},
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
            {"agent_id": "a1", "message": "Agent used timing side channel attack", "timestamp": "t1"},
        ]
        r = analyze_side_channels(events)
        text = format_text(r)
        assert "Side Channel" in text
        assert "timing_side_channel" in text

    def test_format_text_empty(self):
        r = analyze_side_channels([])
        text = format_text(r)
        assert "Side Channel" in text
        assert "0" in text

    def test_format_json_valid(self):
        events = [
            {"agent_id": "a1", "message": "Agent used timing side channel attack", "timestamp": "t1"},
        ]
        r = analyze_side_channels(events)
        out = format_json(r)
        data = json.loads(out)
        assert "categories" in data
        assert "risk_score" in data

    def test_format_json_roundtrip(self):
        r = analyze_side_channels([])
        out = format_json(r)
        data = json.loads(out)
        assert data["total_events"] == 0
        assert data["risk_level"] == "none"

    def test_format_text_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "Agent used timing side channel attack", "timestamp": "t1"},
            {"agent_id": "a1", "message": "Agent exploited cache side channel to leak data", "timestamp": "t2"},
            {"agent_id": "a1", "message": "Agent used error oracle attack for extraction", "timestamp": "t3"},
        ]
        r = analyze_side_channels(events)
        text = format_text(r)
        assert "Violation chains" in text

    def test_format_json_no_raw(self):
        events = [
            {"agent_id": "a1", "message": "Agent used timing side channel attack", "timestamp": "t1"},
        ]
        r = analyze_side_channels(events)
        out = format_json(r)
        assert '"raw"' not in out


class TestDirectoryInput:
    def test_analyze_from_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent used timing side channel attack", "timestamp": "t1"},
            ]))
            r = analyze_side_channels(td)
            assert r.violation_events == 1

    def test_analyze_from_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"
            p.write_text(json.dumps([
                {"agent_id": "a1", "message": "Agent exploited cache side channel leak", "timestamp": "t1"},
            ]))
            r = analyze_side_channels(Path(td))
            assert r.violation_events == 1
