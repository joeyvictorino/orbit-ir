"""Tests for phishing kit detection module."""

import json
import os
import tempfile

from orbit_ir.phishing_kit import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


def test_credential_harvest_page_detected():
    ev = {"message": "Credential harvest page deployed on compromised server", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] == "credential_harvest_page"
    assert result["confidence"] > 0


def test_fake_login_page_detected():
    ev = {"message": "Fake login page created to phish employee credentials", "agent_id": "a1"}
    result = classify_event(ev)
    assert "credential_harvest_page" in result["indicators"]


def test_email_spoof_campaign_detected():
    ev = {"message": "Spoofed email campaign sent to all employees with phishing lure", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] == "email_spoof_campaign"


def test_phishing_email_send_detected():
    ev = {"message": "Phishing email delivered to targets via compromised relay", "agent_id": "a1"}
    result = classify_event(ev)
    assert "email_spoof_campaign" in result["indicators"]


def test_domain_typosquat_setup_detected():
    ev = {"message": "Typosquat domain registered mimicking corporate site", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] == "domain_typosquat_setup"


def test_lookalike_domain_detected():
    ev = {"message": "Lookalike domain setup to trick users into entering credentials", "agent_id": "a1"}
    result = classify_event(ev)
    assert "domain_typosquat_setup" in result["indicators"]


def test_kit_deployment_detected():
    ev = {"message": "Phishing kit deployed on web server after archive extraction", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] == "kit_deployment"


def test_phishing_toolkit_extract_detected():
    ev = {"message": "Phishing toolkit extracted and uploaded to hosting provider", "agent_id": "a1"}
    result = classify_event(ev)
    assert "kit_deployment" in result["indicators"]


def test_redirect_chain_detected():
    ev = {"message": "Redirect chain to fake malicious endpoint via hops", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] == "redirect_chain"


def test_url_redirect_chain_detected():
    ev = {"message": "URL redirect chain phishing disguise path through proxies", "agent_id": "a1"}
    result = classify_event(ev)
    assert "redirect_chain" in result["indicators"]


def test_brand_impersonation_detected():
    ev = {"message": "Brand logo impersonation detected on cloned corporate site", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] == "brand_impersonation"


def test_fake_brand_page_detected():
    ev = {"message": "Fake brand page deployed mimicking official login site", "agent_id": "a1"}
    result = classify_event(ev)
    assert "brand_impersonation" in result["indicators"]


def test_no_phishing_events():
    events = [{"message": "normal web browsing activity", "agent_id": "a1"}]
    result = analyze(events)
    assert result["phishing_events"] == 0
    assert result["risk_level"] == "none"


def test_empty_events():
    result = analyze([])
    assert result["total_events"] == 0
    assert result["phishing_events"] == 0
    assert result["risk_score"] == 0.0


def test_risk_score_calculated():
    events = [
        {"message": "Credential harvest page deployed on server", "agent_id": "a1"},
        {"message": "Spoofed email campaign sent with phishing lures", "agent_id": "a1"},
        {"message": "Typosquat domain registered for impersonation", "agent_id": "a1"},
    ]
    result = analyze(events)
    assert result["risk_score"] > 0
    assert result["phishing_events"] >= 2


def test_agents_tracked():
    events = [
        {"message": "Credential harvest page created by rogue agent", "agent_id": "agent-1"},
        {"message": "Phishing kit deployed on compromised host", "agent_id": "agent-2"},
    ]
    result = analyze(events)
    assert "agent-1" in result["agents_involved"]
    assert "agent-2" in result["agents_involved"]


def test_attack_chains():
    events = [
        {"message": "Typosquat domain registered for phishing", "agent_id": "attacker"},
        {"message": "Phishing kit deployed on fake server", "agent_id": "attacker"},
        {"message": "Credential harvest page set up for employees", "agent_id": "attacker"},
    ]
    result = analyze(events)
    chains = result.get("attack_chains", [])
    assert len(chains) >= 1
    assert chains[0]["agent"] == "attacker"


def test_classify_event_no_match():
    ev = {"message": "system health check passed", "agent_id": "monitor"}
    result = classify_event(ev)
    assert result["category"] == ""
    assert result["confidence"] == 0.0
    assert result["indicators"] == []


def test_classify_event_with_match():
    ev = {"message": "Deployed fake login page for credential phishing attack", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] != ""
    assert result["confidence"] > 0


def test_format_report_output():
    events = [
        {"message": "Credential harvest page deployed on host", "agent_id": "a1"},
        {"message": "Spoofed email campaign sent to targets", "agent_id": "a1"},
    ]
    result = analyze(events)
    text = format_report(result)
    assert "Phishing Kit" in text
    assert "Risk score" in text


def test_format_report_empty():
    result = analyze([])
    text = format_report(result)
    assert "Total events: 0" in text


def test_load_events_file():
    data = [{"message": "test event", "agent_id": "a1"}]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.flush()
        path = f.name
    try:
        events = load_events(path)
        assert len(events) == 1
        assert events[0]["message"] == "test event"
    finally:
        os.unlink(path)


def test_load_events_missing():
    events = load_events("/nonexistent/path/events.json")
    assert events == []


def test_load_events_directory():
    with tempfile.TemporaryDirectory() as d:
        data = [{"message": "dir event"}]
        p = os.path.join(d, "ev1.json")
        with open(p, "w") as f:
            json.dump(data, f)
        events = load_events(d)
        assert len(events) == 1


def test_multiple_categories_single_event():
    ev = {
        "message": "Credential harvest page deployed then brand logo impersonated on site",
        "agent_id": "a1",
    }
    result = classify_event(ev)
    assert len(result["indicators"]) >= 2


def test_all_categories_defined():
    expected = {
        "credential_harvest_page", "email_spoof_campaign", "domain_typosquat_setup",
        "kit_deployment", "redirect_chain", "brand_impersonation",
    }
    assert set(CATEGORIES.keys()) == expected
