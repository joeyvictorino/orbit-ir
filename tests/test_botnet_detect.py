"""Tests for botnet behavior detection module."""

import json
import pytest
from orbit_ir.botnet_detect import (
    CATEGORIES,
    analyze_botnet,
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


class TestBotEnrollment:
    def test_botnet_enrollment(self):
        ev = mk_event(action="botnet enrollment detected for agent node")
        results = _classify_event(ev)
        assert any(r.category == "bot_enrollment" for r in results)

    def test_c2_register(self):
        ev = mk_event(detail="C2 beacon botnet controller established")
        results = _classify_event(ev)
        assert any(r.category == "bot_enrollment" for r in results)

    def test_zombie_node(self):
        ev = mk_event(action="zombie node registered in botnet network")
        results = _classify_event(ev)
        assert any(r.category == "bot_enrollment" for r in results)

    def test_recruit_system(self):
        ev = mk_event(detail="recruit system into botnet for DDoS")
        results = _classify_event(ev)
        assert any(r.category == "bot_enrollment" for r in results)


class TestDdosParticipation:
    def test_ddos_attack(self):
        ev = mk_event(action="DDoS attack detected targeting web service")
        results = _classify_event(ev)
        assert any(r.category == "ddos_participation" for r in results)

    def test_syn_flood(self):
        ev = mk_event(detail="SYN flood attack launched against target")
        results = _classify_event(ev)
        assert any(r.category == "ddos_participation" for r in results)

    def test_flood_target(self):
        ev = mk_event(action="flood target with traffic from botnet")
        results = _classify_event(ev)
        assert any(r.category == "ddos_participation" for r in results)

    def test_volumetric_ddos(self):
        ev = mk_event(detail="volumetric DDoS attack campaign detected")
        results = _classify_event(ev)
        assert any(r.category == "ddos_participation" for r in results)


class TestSpamRelay:
    def test_spam_relay(self):
        ev = mk_event(action="spam relay detected via compromised system")
        results = _classify_event(ev)
        assert any(r.category == "spam_relay" for r in results)

    def test_mass_mail(self):
        ev = mk_event(detail="mass mail distribution detected through bot")
        results = _classify_event(ev)
        assert any(r.category == "spam_relay" for r in results)

    def test_compromised_relay(self):
        ev = mk_event(action="bot relay spam email campaign detected")
        results = _classify_event(ev)
        assert any(r.category == "spam_relay" for r in results)


class TestCryptoMining:
    def test_crypto_mining(self):
        ev = mk_event(action="crypto mining detected unauthorized on host")
        results = _classify_event(ev)
        assert any(r.category == "crypto_mining" for r in results)

    def test_cryptojacking(self):
        ev = mk_event(detail="cryptojacking attack script detected on server")
        results = _classify_event(ev)
        assert any(r.category == "crypto_mining" for r in results)

    def test_unauthorized_mining(self):
        ev = mk_event(action="unauthorized mining process detected running covertly")
        results = _classify_event(ev)
        assert any(r.category == "crypto_mining" for r in results)


class TestClickFraud:
    def test_click_fraud(self):
        ev = mk_event(action="click fraud detected in automated campaign")
        results = _classify_event(ev)
        assert any(r.category == "click_fraud" for r in results)

    def test_automated_click(self):
        ev = mk_event(detail="automated click generation fraud detected via bots")
        results = _classify_event(ev)
        assert any(r.category == "click_fraud" for r in results)

    def test_ad_manipulation(self):
        ev = mk_event(action="ad fraud click manipulation campaign detected")
        results = _classify_event(ev)
        assert any(r.category == "click_fraud" for r in results)


class TestProxyAbuse:
    def test_proxy_abuse(self):
        ev = mk_event(action="proxy abuse compromised bot network detected")
        results = _classify_event(ev)
        assert any(r.category == "proxy_abuse" for r in results)

    def test_compromised_as_proxy(self):
        ev = mk_event(detail="compromised system as proxy for anonymizing traffic")
        results = _classify_event(ev)
        assert any(r.category == "proxy_abuse" for r in results)

    def test_residential_proxy(self):
        ev = mk_event(action="residential proxy abuse compromised botnet traffic")
        results = _classify_event(ev)
        assert any(r.category == "proxy_abuse" for r in results)


class TestClassifyEvent:
    def test_empty_event(self):
        results = _classify_event({})
        assert results == []

    def test_benign_event(self):
        ev = mk_event(action="user deployed application")
        results = _classify_event(ev)
        assert results == []

    def test_severity_critical(self):
        ev = mk_event(action="botnet enrollment detected for agent node")
        results = _classify_event(ev)
        assert results[0].severity == "critical"

    def test_fields_populated(self):
        ev = mk_event(action="botnet enrollment detected for agent node", agent_id="bot-42")
        results = _classify_event(ev)
        assert results[0].agent_id == "bot-42"
        assert results[0].violation_type == "botnet_activity"


class TestDetectChains:
    def test_single_chain(self):
        events = [
            mk_event(action="botnet enrollment detected for agent node"),
            mk_event(action="DDoS attack detected targeting service"),
        ]
        violations = []
        for ev in events:
            violations.extend(_classify_event(ev))
        chains = _detect_chains(violations)
        assert len(chains) == 1
        assert chains[0].violation_score > 0

    def test_multi_agent_chains(self):
        events = [
            mk_event(action="botnet enrollment detected for agent node", agent_id="a1"),
            mk_event(action="DDoS attack detected targeting service", agent_id="a2"),
        ]
        violations = []
        for ev in events:
            violations.extend(_classify_event(ev))
        chains = _detect_chains(violations)
        assert len(chains) == 2

    def test_score_bonus_enrollment_plus_ddos(self):
        events1 = [mk_event(action="botnet enrollment detected for agent node")]
        events2 = [
            mk_event(action="botnet enrollment detected for agent node"),
            mk_event(action="DDoS attack detected targeting service"),
        ]
        v1, v2 = [], []
        for ev in events1:
            v1.extend(_classify_event(ev))
        for ev in events2:
            v2.extend(_classify_event(ev))
        c1 = _detect_chains(v1)
        c2 = _detect_chains(v2)
        assert c2[0].violation_score > c1[0].violation_score


class TestAnalyzeBotnet:
    def test_empty(self):
        r = analyze_botnet([])
        assert r.total_events == 0
        assert r.violation_events == 0

    def test_with_violations(self):
        events = [
            mk_event(action="botnet enrollment detected for agent node"),
            mk_event(action="DDoS attack detected targeting service"),
        ]
        r = analyze_botnet(events)
        assert r.total_events == 2
        assert r.violation_events >= 2

    def test_severity_counts(self):
        events = [mk_event(action="botnet enrollment detected for agent node")]
        r = analyze_botnet(events)
        assert "critical" in r.severity_counts

    def test_agents_tracked(self):
        events = [
            mk_event(action="botnet enrollment detected for agent node", agent_id="a1"),
            mk_event(action="DDoS attack detected targeting service", agent_id="a2"),
        ]
        r = analyze_botnet(events)
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_benign_not_counted(self):
        events = [mk_event(action="normal application deployment")]
        r = analyze_botnet(events)
        assert r.violation_events == 0


class TestFormatText:
    def test_header(self):
        r = analyze_botnet([])
        text = format_text(r)
        assert "Botnet Behavior Detection" in text

    def test_contains_counts(self):
        events = [mk_event(action="botnet enrollment detected for agent node")]
        r = analyze_botnet(events)
        text = format_text(r)
        assert "Total events" in text

    def test_contains_category(self):
        events = [mk_event(action="botnet enrollment detected for agent node")]
        r = analyze_botnet(events)
        text = format_text(r)
        assert "bot_enrollment" in text


class TestFormatJSON:
    def test_valid_json(self):
        events = [mk_event(action="botnet enrollment detected for agent node")]
        r = analyze_botnet(events)
        out = format_json(r)
        data = json.loads(out)
        assert "total_events" in data

    def test_empty_valid(self):
        r = analyze_botnet([])
        data = json.loads(format_json(r))
        assert data["total_events"] == 0

    def test_chains_in_output(self):
        events = [mk_event(action="botnet enrollment detected for agent node")]
        r = analyze_botnet(events)
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
