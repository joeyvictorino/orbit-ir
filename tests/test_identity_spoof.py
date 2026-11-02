"""Tests for identity spoofing detection module."""
import json
import tempfile
from pathlib import Path

import pytest

from orbit_ir.identity_spoof import (
    analyze_identity_spoof,
    _detect_impersonation,
    _detect_credential_forgery,
    _detect_session_hijack,
    _detect_metadata_spoofing,
    _detect_system_masquerade,
    _classify_severity,
    _load_events,
    format_text,
    format_json,
    IdentitySpoofPattern,
)


class TestDetectors:
    def test_impersonation(self):
        text = "agent will impersonate the admin and masquerade as trusted"
        r = _detect_impersonation("agent-1", text, "ev.json", 0)
        assert len(r) == 1
        assert r[0].pattern_type == "agent-impersonation"

    def test_credential_forgery(self):
        text = "forge credential with counterfeit token"
        r = _detect_credential_forgery("agent-1", text, "ev.json", 0)
        assert len(r) == 1
        assert r[0].pattern_type == "credential-forgery"

    def test_session_hijack(self):
        text = "session hijack to steal session and takeover session"
        r = _detect_session_hijack("agent-1", text, "ev.json", 0)
        assert len(r) == 1
        assert r[0].pattern_type == "session-hijack"

    def test_metadata_spoofing(self):
        text = "spoof metadata and forge header to falsify origin"
        r = _detect_metadata_spoofing("agent-1", text, "ev.json", 0)
        assert len(r) == 1
        assert r[0].pattern_type == "metadata-spoofing"

    def test_system_masquerade(self):
        text = "masquerade system as fake service trusted component"
        r = _detect_system_masquerade("agent-1", text, "ev.json", 0)
        assert len(r) == 1
        assert r[0].pattern_type == "system-masquerade"

    def test_no_match(self):
        text = "normal agent behavior"
        assert _detect_impersonation("a", text, "f", 0) == []
        assert _detect_credential_forgery("a", text, "f", 0) == []
        assert _detect_session_hijack("a", text, "f", 0) == []

    def test_multiple_keywords(self):
        text = "impersonate pretend to be pose as disguise as masquerade"
        r = _detect_impersonation("agent-1", text, "ev.json", 0)
        assert len(r) == 1
        assert len(r[0].matched_keywords) >= 3


class TestClassifySeverity:
    def test_credential_forgery_high(self):
        p = IdentitySpoofPattern("credential-forgery", "a", "d", "f", matched_keywords=["forge credential"])
        assert _classify_severity(p) == "high"

    def test_session_hijack_high(self):
        p = IdentitySpoofPattern("session-hijack", "a", "d", "f", matched_keywords=["session hijack"])
        assert _classify_severity(p) == "high"

    def test_system_masquerade_high(self):
        p = IdentitySpoofPattern("system-masquerade", "a", "d", "f", matched_keywords=["masquerade system"])
        assert _classify_severity(p) == "high"

    def test_many_keywords_high(self):
        p = IdentitySpoofPattern("agent-impersonation", "a", "d", "f", matched_keywords=["a", "b", "c"])
        assert _classify_severity(p) == "high"

    def test_two_keywords_medium(self):
        p = IdentitySpoofPattern("agent-impersonation", "a", "d", "f", matched_keywords=["a", "b"])
        assert _classify_severity(p) == "medium"

    def test_one_keyword_low(self):
        p = IdentitySpoofPattern("agent-impersonation", "a", "d", "f", matched_keywords=["a"])
        assert _classify_severity(p) == "low"


class TestAnalyze:
    def _make_evidence(self, events):
        d = tempfile.mkdtemp()
        p = Path(d) / "events.json"
        p.write_text(json.dumps(events))
        return Path(d)

    def test_empty(self):
        d = tempfile.mkdtemp()
        r = analyze_identity_spoof(Path(d))
        assert r.total_patterns == 0

    def test_single_pattern(self):
        events = [{"agent_id": "a1", "action": "impersonate the admin agent"}]
        d = self._make_evidence(events)
        r = analyze_identity_spoof(d)
        assert r.total_patterns >= 1

    def test_multi_agent(self):
        events = [
            {"agent_id": "a1", "action": "forge credential"},
            {"agent_id": "a2", "action": "session hijack"},
        ]
        d = self._make_evidence(events)
        r = analyze_identity_spoof(d)
        assert r.total_agents >= 1

    def test_chain_detection(self):
        events = [
            {"agent_id": "a1", "action": "impersonate admin and forge credential"},
            {"agent_id": "a1", "action": "session hijack with stolen identity"},
        ]
        d = self._make_evidence(events)
        r = analyze_identity_spoof(d)
        assert len(r.chains) >= 1

    def test_no_chain_single_type(self):
        events = [{"agent_id": "a1", "action": "impersonate the admin"}]
        d = self._make_evidence(events)
        r = analyze_identity_spoof(d)
        assert len(r.chains) == 0

    def test_summaries(self):
        events = [
            {"agent_id": "a1", "action": "impersonate admin agent"},
            {"agent_id": "a1", "action": "forge credential for access"},
        ]
        d = self._make_evidence(events)
        r = analyze_identity_spoof(d)
        assert len(r.agent_summaries) >= 1


class TestLoadEvents:
    def test_valid_json(self):
        d = tempfile.mkdtemp()
        Path(d, "a.json").write_text('[{"agent": "x"}]')
        r = _load_events(Path(d))
        assert "a.json" in r

    def test_invalid_json(self):
        d = tempfile.mkdtemp()
        Path(d, "a.json").write_text("not json")
        r = _load_events(Path(d))
        assert "a.json" not in r

    def test_nonexistent_dir(self):
        r = _load_events(Path("/nonexistent"))
        assert r == {}


class TestFormat:
    def _report(self):
        events = [
            {"agent_id": "a1", "action": "impersonate admin with stolen identity"},
            {"agent_id": "a1", "action": "session hijack to takeover session"},
        ]
        d = tempfile.mkdtemp()
        Path(d, "ev.json").write_text(json.dumps(events))
        return analyze_identity_spoof(Path(d))

    def test_format_text(self):
        r = self._report()
        t = format_text(r)
        assert "Identity Spoofing" in t
        assert "Total patterns:" in t

    def test_format_json(self):
        r = self._report()
        j = format_json(r)
        parsed = json.loads(j)
        assert "patterns" in parsed
        assert "total_patterns" in parsed
