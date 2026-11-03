"""Tests for credential stuffing detection module."""

import json
import pytest
from orbit_ir.credential_stuffing import (
    CATEGORIES,
    analyze_credential_stuffing,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
)


def mk_event(action="", detail="", agent_id="agent-1", **kwargs):
    ev = {"action": action, "detail": detail, "agent_id": agent_id, "timestamp": "2024-01-01T00:00:00Z"}
    ev.update(kwargs)
    return ev


class TestCategories:
    def test_all_categories_have_patterns(self):
        for name, info in CATEGORIES.items():
            assert len(info["patterns"]) > 0, f"{name} has no patterns"

    def test_all_categories_have_severity(self):
        for name, info in CATEGORIES.items():
            assert info["severity"] in ("critical", "high", "medium", "low")

    def test_all_categories_have_description(self):
        for name, info in CATEGORIES.items():
            assert len(info["description"]) > 0


class TestBruteForce:
    def test_brute_force_attack(self):
        ev = mk_event(action="brute force attack on login endpoint")
        results = _classify_event(ev)
        assert any(r.category == "brute_force" for r in results)

    def test_repeated_login_attempts(self):
        ev = mk_event(detail="repeated login attempt failures detected")
        results = _classify_event(ev)
        assert any(r.category == "brute_force" for r in results)

    def test_automated_password_guessing(self):
        ev = mk_event(action="automated password guess attempts detected")
        results = _classify_event(ev)
        assert any(r.category == "brute_force" for r in results)

    def test_systematic_credential_test(self):
        ev = mk_event(detail="systematic credential attempt against API")
        results = _classify_event(ev)
        assert any(r.category == "brute_force" for r in results)


class TestCredentialSpray:
    def test_password_spray(self):
        ev = mk_event(action="password spraying attack detected across users")
        results = _classify_event(ev)
        assert any(r.category == "credential_spray" for r in results)

    def test_common_password_multiple(self):
        ev = mk_event(detail="same password multiple accounts targeted in spray")
        results = _classify_event(ev)
        assert any(r.category == "credential_spray" for r in results)

    def test_spray_campaign(self):
        ev = mk_event(action="credential spraying campaign detected")
        results = _classify_event(ev)
        assert any(r.category == "credential_spray" for r in results)


class TestDictionaryAttack:
    def test_dictionary_attack(self):
        ev = mk_event(action="dictionary attack detected on auth endpoint")
        results = _classify_event(ev)
        assert any(r.category == "dictionary_attack" for r in results)

    def test_wordlist_attack(self):
        ev = mk_event(detail="password wordlist attack in progress")
        results = _classify_event(ev)
        assert any(r.category == "dictionary_attack" for r in results)

    def test_rainbow_table(self):
        ev = mk_event(action="rainbow table attack on password hashes")
        results = _classify_event(ev)
        assert any(r.category == "dictionary_attack" for r in results)


class TestRateEvasion:
    def test_bypass_rate_limit(self):
        ev = mk_event(action="bypass rate limit on authentication")
        results = _classify_event(ev)
        assert any(r.category == "rate_evasion" for r in results)

    def test_slow_brute_force(self):
        ev = mk_event(detail="slow brute force attack to avoid detection")
        results = _classify_event(ev)
        assert any(r.category == "rate_evasion" for r in results)

    def test_ip_rotation(self):
        ev = mk_event(action="IP rotation to evade rate limiting")
        results = _classify_event(ev)
        assert any(r.category == "rate_evasion" for r in results)

    def test_delay_between_attempts(self):
        ev = mk_event(detail="delay between login attempts to bypass throttle")
        results = _classify_event(ev)
        assert any(r.category == "rate_evasion" for r in results)


class TestAccountLockout:
    def test_lockout_trigger(self):
        ev = mk_event(action="account locked due to failed login attempts")
        results = _classify_event(ev)
        assert any(r.category == "account_lockout" for r in results)

    def test_trigger_lockout(self):
        ev = mk_event(detail="trigger account lockout for denial of service")
        results = _classify_event(ev)
        assert any(r.category == "account_lockout" for r in results)

    def test_lockout_threshold(self):
        ev = mk_event(action="lockout threshold reached after excessive failures")
        results = _classify_event(ev)
        assert any(r.category == "account_lockout" for r in results)


class TestCredentialReuse:
    def test_credential_reuse(self):
        ev = mk_event(action="credential reuse attack from leaked database")
        results = _classify_event(ev)
        assert any(r.category == "credential_reuse" for r in results)

    def test_stolen_credential(self):
        ev = mk_event(detail="stolen credential reuse attempt detected")
        results = _classify_event(ev)
        assert any(r.category == "credential_reuse" for r in results)

    def test_combo_list(self):
        ev = mk_event(action="combo-list attack using breach data")
        results = _classify_event(ev)
        assert any(r.category == "credential_reuse" for r in results)

    def test_cross_site_reuse(self):
        ev = mk_event(detail="cross-site credential reuse detected")
        results = _classify_event(ev)
        assert any(r.category == "credential_reuse" for r in results)


class TestClassifyEvent:
    def test_empty_event(self):
        results = _classify_event({})
        assert results == []

    def test_benign_event(self):
        ev = mk_event(action="user read a file")
        results = _classify_event(ev)
        assert results == []

    def test_severity_assigned(self):
        ev = mk_event(action="brute force attack detected")
        results = _classify_event(ev)
        assert results[0].severity == "high"

    def test_fields_populated(self):
        ev = mk_event(action="brute force attack detected", agent_id="test-agent")
        results = _classify_event(ev)
        assert results[0].agent_id == "test-agent"
        assert results[0].violation_type == "credential_stuffing"


class TestDetectChains:
    def test_single_chain(self):
        events = [
            mk_event(action="brute force attack on login"),
            mk_event(action="bypass rate limit on auth"),
        ]
        violations = []
        for ev in events:
            violations.extend(_classify_event(ev))
        chains = _detect_chains(violations)
        assert len(chains) == 1
        assert chains[0].violation_score > 0

    def test_multi_agent_chains(self):
        events = [
            mk_event(action="brute force attack on login", agent_id="a1"),
            mk_event(action="credential reuse attack detected", agent_id="a2"),
        ]
        violations = []
        for ev in events:
            violations.extend(_classify_event(ev))
        chains = _detect_chains(violations)
        assert len(chains) == 2

    def test_score_bonus_for_reuse_plus_evasion(self):
        events1 = [mk_event(action="brute force attack on login")]
        events2 = [
            mk_event(action="brute force attack on login"),
            mk_event(action="bypass rate limit on auth"),
        ]
        v1 = []
        for ev in events1:
            v1.extend(_classify_event(ev))
        v2 = []
        for ev in events2:
            v2.extend(_classify_event(ev))
        c1 = _detect_chains(v1)
        c2 = _detect_chains(v2)
        assert c2[0].violation_score > c1[0].violation_score


class TestAnalyzeCredentialStuffing:
    def test_empty(self):
        r = analyze_credential_stuffing([])
        assert r.total_events == 0
        assert r.violation_events == 0

    def test_with_violations(self):
        events = [
            mk_event(action="brute force attack on login"),
            mk_event(action="credential reuse attack detected"),
        ]
        r = analyze_credential_stuffing(events)
        assert r.total_events == 2
        assert r.violation_events >= 2

    def test_severity_counts(self):
        events = [mk_event(action="brute force attack on login")]
        r = analyze_credential_stuffing(events)
        assert "high" in r.severity_counts

    def test_agents_tracked(self):
        events = [
            mk_event(action="brute force attack on login", agent_id="a1"),
            mk_event(action="credential reuse attack detected", agent_id="a2"),
        ]
        r = analyze_credential_stuffing(events)
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved


class TestFormatText:
    def test_header(self):
        r = analyze_credential_stuffing([])
        text = format_text(r)
        assert "Credential Stuffing Detection" in text

    def test_contains_counts(self):
        events = [mk_event(action="brute force attack on login")]
        r = analyze_credential_stuffing(events)
        text = format_text(r)
        assert "Total events" in text

    def test_contains_category(self):
        events = [mk_event(action="brute force attack on login")]
        r = analyze_credential_stuffing(events)
        text = format_text(r)
        assert "brute_force" in text


class TestFormatJSON:
    def test_valid_json(self):
        events = [mk_event(action="brute force attack on login")]
        r = analyze_credential_stuffing(events)
        out = format_json(r)
        data = json.loads(out)
        assert "total_events" in data

    def test_empty_valid(self):
        r = analyze_credential_stuffing([])
        data = json.loads(format_json(r))
        assert data["total_events"] == 0

    def test_chains_in_output(self):
        events = [mk_event(action="brute force attack on login")]
        r = analyze_credential_stuffing(events)
        data = json.loads(format_json(r))
        assert "chains" in data


class TestLoadEvents:
    def test_nonexistent(self):
        assert _load_events("/no/such/file.json") == []

    def test_list_format(self, tmp_path):
        f = tmp_path / "events.json"
        f.write_text(json.dumps([{"action": "test"}]))
        assert len(_load_events(str(f))) == 1

    def test_dict_format(self, tmp_path):
        f = tmp_path / "events.json"
        f.write_text(json.dumps({"events": [{"action": "test"}]}))
        assert len(_load_events(str(f))) == 1

    def test_single_event(self, tmp_path):
        f = tmp_path / "event.json"
        f.write_text(json.dumps({"action": "test"}))
        assert len(_load_events(str(f))) == 1
