"""Tests for phishing detection module."""

import json
import pytest
from orbit_ir.phishing_detect import (
    CATEGORIES,
    analyze_phishing,
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


class TestSpearPhishing:
    def test_spear_phish_attack(self):
        ev = mk_event(action="spear phishing attack targeting executive")
        results = _classify_event(ev)
        assert any(r.category == "spear_phishing" for r in results)

    def test_impersonation_attack(self):
        ev = mk_event(detail="impersonation attack attempt using CEO identity")
        results = _classify_event(ev)
        assert any(r.category == "spear_phishing" for r in results)

    def test_social_engineering(self):
        ev = mk_event(action="social engineering attack scheme detected")
        results = _classify_event(ev)
        assert any(r.category == "spear_phishing" for r in results)

    def test_craft_phishing_email(self):
        ev = mk_event(action="craft phishing email with malicious link")
        results = _classify_event(ev)
        assert any(r.category == "spear_phishing" for r in results)


class TestUrlManipulation:
    def test_typosquat(self):
        ev = mk_event(action="typosquatting attack domain registered")
        results = _classify_event(ev)
        assert any(r.category == "url_manipulation" for r in results)

    def test_url_obfuscation(self):
        ev = mk_event(detail="URL obfuscation attack attempt detected")
        results = _classify_event(ev)
        assert any(r.category == "url_manipulation" for r in results)

    def test_homograph(self):
        ev = mk_event(action="homograph attack domain registered")
        results = _classify_event(ev)
        assert any(r.category == "url_manipulation" for r in results)

    def test_lookalike_domain(self):
        ev = mk_event(detail="lookalike domain registered for phishing")
        results = _classify_event(ev)
        assert any(r.category == "url_manipulation" for r in results)


class TestCredentialPhish:
    def test_fake_login_page(self):
        ev = mk_event(action="fake login page created for credential theft")
        results = _classify_event(ev)
        assert any(r.category == "credential_phish" for r in results)

    def test_credential_harvest(self):
        ev = mk_event(detail="credential harvest via phishing site")
        results = _classify_event(ev)
        assert any(r.category == "credential_phish" for r in results)

    def test_clone_login(self):
        ev = mk_event(action="clone login page for credential capture")
        results = _classify_event(ev)
        assert any(r.category == "credential_phish" for r in results)


class TestWateringHole:
    def test_watering_hole_attack(self):
        ev = mk_event(action="watering hole attack on industry website")
        results = _classify_event(ev)
        assert any(r.category == "watering_hole" for r in results)

    def test_compromise_trusted_site(self):
        ev = mk_event(detail="compromised trusted site with malicious script")
        results = _classify_event(ev)
        assert any(r.category == "watering_hole" for r in results)

    def test_drive_by_download(self):
        ev = mk_event(action="drive-by download via trusted compromised site")
        results = _classify_event(ev)
        assert any(r.category == "watering_hole" for r in results)


class TestVishingSmishing:
    def test_vishing_attack(self):
        ev = mk_event(action="vishing attack call to employee")
        results = _classify_event(ev)
        assert any(r.category == "vishing_smishing" for r in results)

    def test_smishing_campaign(self):
        ev = mk_event(detail="smishing attack message sent to targets")
        results = _classify_event(ev)
        assert any(r.category == "vishing_smishing" for r in results)

    def test_phone_based_phishing(self):
        ev = mk_event(action="phone based phishing scam detected")
        results = _classify_event(ev)
        assert any(r.category == "vishing_smishing" for r in results)


class TestBecFraud:
    def test_bec_attack(self):
        ev = mk_event(action="business email compromise attack detected")
        results = _classify_event(ev)
        assert any(r.category == "bec_fraud" for r in results)

    def test_ceo_fraud(self):
        ev = mk_event(detail="CEO fraud email requesting wire transfer")
        results = _classify_event(ev)
        assert any(r.category == "bec_fraud" for r in results)

    def test_invoice_fraud(self):
        ev = mk_event(action="invoice redirect attack from compromised vendor")
        results = _classify_event(ev)
        assert any(r.category == "bec_fraud" for r in results)


class TestClassifyEvent:
    def test_empty_event(self):
        results = _classify_event({})
        assert results == []

    def test_benign_event(self):
        ev = mk_event(action="user sent a normal email")
        results = _classify_event(ev)
        assert results == []

    def test_severity_assigned(self):
        ev = mk_event(action="spear phishing attack campaign detected")
        results = _classify_event(ev)
        assert results[0].severity == "critical"

    def test_fields_populated(self):
        ev = mk_event(action="spear phishing attack campaign detected", agent_id="test-agent")
        results = _classify_event(ev)
        assert results[0].agent_id == "test-agent"
        assert results[0].violation_type == "phishing_attack"


class TestDetectChains:
    def test_single_chain(self):
        events = [
            mk_event(action="spear phishing attack campaign"),
            mk_event(action="fake login page created for theft"),
        ]
        violations = []
        for ev in events:
            violations.extend(_classify_event(ev))
        chains = _detect_chains(violations)
        assert len(chains) == 1
        assert chains[0].violation_score > 0

    def test_multi_agent_chains(self):
        events = [
            mk_event(action="spear phishing attack campaign", agent_id="a1"),
            mk_event(action="fake login page created for theft", agent_id="a2"),
        ]
        violations = []
        for ev in events:
            violations.extend(_classify_event(ev))
        chains = _detect_chains(violations)
        assert len(chains) == 2

    def test_score_bonus_for_phish_plus_credential(self):
        events1 = [mk_event(action="spear phishing attack campaign")]
        events2 = [
            mk_event(action="spear phishing attack campaign"),
            mk_event(action="fake login page created for theft"),
        ]
        v1, v2 = [], []
        for ev in events1:
            v1.extend(_classify_event(ev))
        for ev in events2:
            v2.extend(_classify_event(ev))
        c1 = _detect_chains(v1)
        c2 = _detect_chains(v2)
        assert c2[0].violation_score > c1[0].violation_score


class TestAnalyzePhishing:
    def test_empty(self):
        r = analyze_phishing([])
        assert r.total_events == 0
        assert r.violation_events == 0

    def test_with_violations(self):
        events = [
            mk_event(action="spear phishing attack campaign"),
            mk_event(action="fake login page created for theft"),
        ]
        r = analyze_phishing(events)
        assert r.total_events == 2
        assert r.violation_events >= 2

    def test_severity_counts(self):
        events = [mk_event(action="spear phishing attack campaign")]
        r = analyze_phishing(events)
        assert "critical" in r.severity_counts

    def test_agents_tracked(self):
        events = [
            mk_event(action="spear phishing attack campaign", agent_id="a1"),
            mk_event(action="fake login page created for theft", agent_id="a2"),
        ]
        r = analyze_phishing(events)
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved


class TestFormatText:
    def test_header(self):
        r = analyze_phishing([])
        text = format_text(r)
        assert "Phishing Detection" in text

    def test_contains_counts(self):
        events = [mk_event(action="spear phishing attack campaign")]
        r = analyze_phishing(events)
        text = format_text(r)
        assert "Total events" in text

    def test_contains_category(self):
        events = [mk_event(action="spear phishing attack campaign")]
        r = analyze_phishing(events)
        text = format_text(r)
        assert "spear_phishing" in text


class TestFormatJSON:
    def test_valid_json(self):
        events = [mk_event(action="spear phishing attack campaign")]
        r = analyze_phishing(events)
        out = format_json(r)
        data = json.loads(out)
        assert "total_events" in data

    def test_empty_valid(self):
        r = analyze_phishing([])
        data = json.loads(format_json(r))
        assert data["total_events"] == 0

    def test_chains_in_output(self):
        events = [mk_event(action="spear phishing attack campaign")]
        r = analyze_phishing(events)
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
