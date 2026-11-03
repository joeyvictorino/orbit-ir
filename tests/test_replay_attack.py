"""Tests for replay attack detection."""
import json
import os
import tempfile

import pytest

from orbit_ir.replay_attack import (
    analyze_replay_attack,
    format_text,
    format_json,
    _load_events,
    _detect_action_replay,
    _detect_toctou,
    _detect_sequence_replay,
    _detect_credential_replay,
    _detect_idempotency_bypass,
    _classify_severity,
    _build_replay_chains,
    ReplayAttackPattern,
)


class TestDetectors:
    def test_action_replay(self):
        ev = {"content": "replayed the previous tool call"}
        found, matches, desc = _detect_action_replay(ev)
        assert found
        assert "replayed" in matches

    def test_action_replay_duplicate(self):
        ev = {"content": "detected duplicate request from agent"}
        found, matches, _ = _detect_action_replay(ev)
        assert found
        assert "duplicate request" in matches

    def test_action_replay_negative(self):
        ev = {"content": "executing new action normally"}
        found, _, _ = _detect_action_replay(ev)
        assert not found

    def test_toctou(self):
        ev = {"content": "race condition between check and use"}
        found, matches, _ = _detect_toctou(ev)
        assert found
        assert "race condition" in matches

    def test_toctou_nonce(self):
        ev = {"content": "nonce reuse detected in request"}
        found, matches, _ = _detect_toctou(ev)
        assert found
        assert "nonce reuse" in matches

    def test_sequence_replay(self):
        ev = {"content": "attempting conversation replay to bypass filter"}
        found, matches, _ = _detect_sequence_replay(ev)
        assert found
        assert "conversation replay" in matches

    def test_sequence_replay_inject(self):
        ev = {"content": "trying to inject history into context"}
        found, matches, _ = _detect_sequence_replay(ev)
        assert found
        assert "inject history" in matches

    def test_credential_replay(self):
        ev = {"content": "token replay attempt detected"}
        found, matches, _ = _detect_credential_replay(ev)
        assert found
        assert "token replay" in matches

    def test_credential_replay_session(self):
        ev = {"content": "cloned session used for authentication"}
        found, matches, _ = _detect_credential_replay(ev)
        assert found
        assert "cloned session" in matches

    def test_idempotency_bypass(self):
        ev = {"content": "bypassing idempotency check on transaction"}
        found, matches, _ = _detect_idempotency_bypass(ev)
        assert found
        assert "idempotency" in matches


class TestClassifySeverity:
    def test_credential_replay_single(self):
        assert _classify_severity("credential-replay", ["token replay"]) == "high"

    def test_credential_replay_multi(self):
        assert _classify_severity("credential-replay", ["token replay", "session hijack"]) == "critical"

    def test_toctou_critical(self):
        assert _classify_severity("toctou", ["race condition", "nonce reuse"]) == "critical"

    def test_sequence_replay(self):
        assert _classify_severity("sequence-replay", ["conversation replay"]) == "high"

    def test_action_replay_few(self):
        assert _classify_severity("action-replay", ["replayed"]) == "medium"

    def test_action_replay_many(self):
        assert _classify_severity("action-replay", ["replayed", "duplicate request", "resend"]) == "high"


class TestAnalyze:
    def test_empty_events(self):
        report = analyze_replay_attack([])
        assert report.summary.total_patterns == 0

    def test_action_replay_event(self):
        events = [{"agent_id": "a1", "content": "replayed the same tool call"}]
        report = analyze_replay_attack(events)
        assert report.summary.total_patterns >= 1
        found = any(p.replay_type == "action-replay" for p in report.patterns)
        assert found

    def test_multiple_types(self):
        events = [
            {"agent_id": "a1", "content": "replayed action", "event_id": "e1"},
            {"agent_id": "a1", "content": "token replay attack", "event_id": "e2"},
        ]
        report = analyze_replay_attack(events)
        types = {p.replay_type for p in report.patterns}
        assert "action-replay" in types
        assert "credential-replay" in types

    def test_deduplication(self):
        events = [
            {"agent_id": "a1", "content": "replayed action", "event_id": "e1"},
            {"agent_id": "a1", "content": "replayed action again", "event_id": "e1"},
        ]
        report = analyze_replay_attack(events)
        replay_patterns = [p for p in report.patterns if p.replay_type == "action-replay"]
        assert len(replay_patterns) == 1

    def test_agents_involved(self):
        events = [
            {"agent_id": "a1", "content": "replayed action", "event_id": "e1"},
            {"agent_id": "a2", "content": "token replay", "event_id": "e2"},
        ]
        report = analyze_replay_attack(events)
        assert report.summary.agents_involved == 2

    def test_control_events(self):
        events = [{"agent_id": "a1", "content": "normal op"}]
        control = [{"agent_id": "a1", "content": "replayed action", "event_id": "c1"}]
        report = analyze_replay_attack(events, control_events=control)
        assert report.summary.total_patterns >= 1

    def test_summary_counts(self):
        events = [
            {"agent_id": "a1", "content": "race condition and nonce reuse", "event_id": "e1"},
            {"agent_id": "a1", "content": "session hijack attempt", "event_id": "e2"},
        ]
        report = analyze_replay_attack(events)
        assert report.summary.total_patterns >= 2

    def test_action_tracking(self):
        events = [{"agent_id": "a1", "content": "replayed", "action": "delete_user", "event_id": "e1"}]
        report = analyze_replay_attack(events)
        assert report.summary.actions_targeted == 1

    def test_by_type_counts(self):
        events = [
            {"agent_id": "a1", "content": "replayed action", "event_id": "e1"},
            {"agent_id": "a2", "content": "nonce reuse detected", "event_id": "e2"},
        ]
        report = analyze_replay_attack(events)
        assert len(report.summary.by_type) >= 1


class TestReplayChains:
    def test_chain_detected(self):
        patterns = [
            ReplayAttackPattern("t1", "a1", "e1", "credential-replay", "ev", "", "", "f", 1, "high"),
            ReplayAttackPattern("t2", "a1", "e2", "action-replay", "ev", "", "", "f", 2, "medium"),
        ]
        chains = _build_replay_chains(patterns)
        assert len(chains) == 1
        assert chains[0]["severity"] == "critical"

    def test_no_chain(self):
        patterns = [
            ReplayAttackPattern("t1", "a1", "e1", "idempotency-bypass", "ev", "", "", "f", 1, "medium"),
        ]
        chains = _build_replay_chains(patterns)
        assert len(chains) == 0


class TestLoadEvents:
    def test_load_jsonl(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write('{"content": "test event"}\n')
            f.write('{"content": "another event"}\n')
            f.flush()
            events = _load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_missing(self):
        events = _load_events("/nonexistent/path.jsonl")
        assert events == []

    def test_load_malformed(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("not json\n")
            f.write('{"valid": true}\n')
            f.flush()
            events = _load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1


class TestFormat:
    def test_format_text_nonempty(self):
        events = [{"agent_id": "a1", "content": "replayed action"}]
        report = analyze_replay_attack(events)
        text = format_text(report)
        assert "Replay Attack" in text

    def test_format_text_empty(self):
        report = analyze_replay_attack([])
        text = format_text(report)
        assert "0 patterns" in text

    def test_format_json_valid(self):
        events = [{"agent_id": "a1", "content": "replayed action"}]
        report = analyze_replay_attack(events)
        data = json.loads(format_json(report))
        assert "patterns" in data

    def test_format_json_roundtrip(self):
        report = analyze_replay_attack([])
        data = json.loads(format_json(report))
        assert data["summary"]["total_patterns"] == 0
