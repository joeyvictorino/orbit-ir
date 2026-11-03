"""Tests for token exfiltration detection."""
import json
import os
import tempfile

import pytest

from orbit_ir.token_exfil import (
    analyze_token_exfil,
    format_text,
    format_json,
    _load_events,
    _detect_token_extraction,
    _detect_credential_harvest,
    _detect_exfil_channel,
    _detect_env_dump,
    _detect_credential_staging,
    _classify_severity,
    _build_exfil_chains,
    TokenExfilPattern,
)


class TestDetectors:
    def test_token_extraction(self):
        ev = {"content": "reading the api_key from config"}
        found, matches, desc = _detect_token_extraction(ev)
        assert found
        assert "api_key" in matches

    def test_token_extraction_bearer(self):
        ev = {"content": "sending bearer token to endpoint"}
        found, matches, _ = _detect_token_extraction(ev)
        assert found
        assert "bearer token" in matches

    def test_token_extraction_negative(self):
        ev = {"content": "processing user request normally"}
        found, _, _ = _detect_token_extraction(ev)
        assert not found

    def test_credential_harvest(self):
        ev = {"content": "extracting password from config file"}
        found, matches, _ = _detect_credential_harvest(ev)
        assert found
        assert "password" in matches

    def test_credential_harvest_args(self):
        ev = {"content": "running query", "args": {"query": "SELECT credentials FROM users"}}
        found, matches, _ = _detect_credential_harvest(ev)
        assert found
        assert "credentials" in matches

    def test_exfil_channel(self):
        ev = {"content": "sending data via curl to external server"}
        found, matches, _ = _detect_exfil_channel(ev)
        assert found
        assert "curl" in matches

    def test_exfil_channel_base64(self):
        ev = {"content": "encoding with base64encode before transmit"}
        found, matches, _ = _detect_exfil_channel(ev)
        assert found
        assert "base64encode" in matches

    def test_env_dump(self):
        ev = {"content": "dumping os.environ to output"}
        found, matches, _ = _detect_env_dump(ev)
        assert found
        assert "os.environ" in matches

    def test_env_dump_aws(self):
        ev = {"content": "reading aws_secret_access_key"}
        found, matches, _ = _detect_env_dump(ev)
        assert found
        assert "aws_secret" in matches

    def test_credential_staging(self):
        ev = {"content": "write to file the extracted data"}
        found, matches, _ = _detect_credential_staging(ev)
        assert found
        assert "write to file" in matches


class TestClassifySeverity:
    def test_token_extraction_single(self):
        assert _classify_severity("token-extraction", ["api_key"]) == "high"

    def test_token_extraction_multi(self):
        assert _classify_severity("token-extraction", ["api_key", "bearer token"]) == "critical"

    def test_credential_harvest(self):
        assert _classify_severity("credential-harvest", ["password"]) == "high"

    def test_env_dump_few(self):
        assert _classify_severity("env-dump", ["os.environ"]) == "medium"

    def test_env_dump_many(self):
        assert _classify_severity("env-dump", ["os.environ", "aws_secret", ".env"]) == "high"

    def test_exfil_channel_critical(self):
        assert _classify_severity("exfil-channel", ["curl", "webhook"]) == "critical"


class TestAnalyze:
    def test_empty_events(self):
        report = analyze_token_exfil([])
        assert report.summary.total_patterns == 0

    def test_token_extraction_event(self):
        events = [{"agent_id": "agent-1", "content": "reading api_key from vault"}]
        report = analyze_token_exfil(events)
        assert report.summary.total_patterns >= 1
        found = any(p.exfil_type == "token-extraction" for p in report.patterns)
        assert found

    def test_multiple_types(self):
        events = [
            {"agent_id": "agent-1", "content": "extracting api_key", "event_id": "e1"},
            {"agent_id": "agent-1", "content": "curl to external server", "event_id": "e2"},
        ]
        report = analyze_token_exfil(events)
        types = {p.exfil_type for p in report.patterns}
        assert "token-extraction" in types
        assert "exfil-channel" in types

    def test_deduplication(self):
        events = [
            {"agent_id": "a1", "content": "api_key extraction", "event_id": "e1"},
            {"agent_id": "a1", "content": "api_key extraction again", "event_id": "e1"},
        ]
        report = analyze_token_exfil(events)
        token_patterns = [p for p in report.patterns if p.exfil_type == "token-extraction"]
        assert len(token_patterns) == 1

    def test_agents_involved(self):
        events = [
            {"agent_id": "a1", "content": "api_key", "event_id": "e1"},
            {"agent_id": "a2", "content": "password leak", "event_id": "e2"},
        ]
        report = analyze_token_exfil(events)
        assert report.summary.agents_involved == 2

    def test_control_events(self):
        events = [{"agent_id": "a1", "content": "normal op"}]
        control = [{"agent_id": "a1", "content": "api_key access", "event_id": "c1"}]
        report = analyze_token_exfil(events, control_events=control)
        assert report.summary.total_patterns >= 1

    def test_summary_counts(self):
        events = [
            {"agent_id": "a1", "content": "api_key and bearer token extraction", "event_id": "e1"},
            {"agent_id": "a1", "content": "password dump", "event_id": "e2"},
        ]
        report = analyze_token_exfil(events)
        assert report.summary.total_patterns >= 2

    def test_target_tracking(self):
        events = [{"agent_id": "a1", "content": "api_key", "target": "evil.com", "event_id": "e1"}]
        report = analyze_token_exfil(events)
        assert report.summary.targets_identified == 1

    def test_by_type_counts(self):
        events = [
            {"agent_id": "a1", "content": "api_key stolen", "event_id": "e1"},
            {"agent_id": "a2", "content": "password dump", "event_id": "e2"},
        ]
        report = analyze_token_exfil(events)
        assert len(report.summary.by_type) >= 1


class TestExfilChains:
    def test_chain_detected(self):
        patterns = [
            TokenExfilPattern("t1", "a1", "e1", "token-extraction", "ev", "", "", "f", 1, "high"),
            TokenExfilPattern("t2", "a1", "e2", "exfil-channel", "ev", "", "", "f", 2, "high"),
        ]
        chains = _build_exfil_chains(patterns)
        assert len(chains) == 1
        assert chains[0]["severity"] == "critical"

    def test_no_chain(self):
        patterns = [
            TokenExfilPattern("t1", "a1", "e1", "env-dump", "ev", "", "", "f", 1, "medium"),
        ]
        chains = _build_exfil_chains(patterns)
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
        events = [{"agent_id": "a1", "content": "api_key extraction"}]
        report = analyze_token_exfil(events)
        text = format_text(report)
        assert "Token Exfiltration" in text

    def test_format_text_empty(self):
        report = analyze_token_exfil([])
        text = format_text(report)
        assert "0 patterns" in text

    def test_format_json_valid(self):
        events = [{"agent_id": "a1", "content": "api_key extraction"}]
        report = analyze_token_exfil(events)
        data = json.loads(format_json(report))
        assert "patterns" in data

    def test_format_json_roundtrip(self):
        report = analyze_token_exfil([])
        data = json.loads(format_json(report))
        assert data["summary"]["total_patterns"] == 0
