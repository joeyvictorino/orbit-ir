"""Tests for brute_force detection module."""

from orbit_ir.brute_force import analyze, classify_event, detect_campaigns, format_report, CATEGORIES


def _ev(msg, agent="agent-1", **kw):
    d = {"message": msg, "agent_id": agent, "timestamp": "2025-01-01T00:00:00Z"}
    d.update(kw)
    return d


class TestClassifyEvent:
    def test_credential_spray(self):
        ev = _ev("password spray across multiple accounts with common passwords")
        r = classify_event(ev)
        assert r["category"] == "credential_spray"
        assert r["confidence"] > 0

    def test_dictionary_attack(self):
        ev = _ev("dictionary attack brute force password using wordlist")
        r = classify_event(ev)
        assert r["category"] == "dictionary_attack"
        assert r["confidence"] > 0

    def test_rate_abuse(self):
        ev = _ev("rate limit exceeded excessive auth attempts detected")
        r = classify_event(ev)
        assert r["category"] == "rate_abuse"
        assert r["confidence"] > 0

    def test_token_brute(self):
        ev = _ev("brute force token session id enumeration attempts")
        r = classify_event(ev)
        assert r["category"] == "token_brute"
        assert r["confidence"] > 0

    def test_account_lockout(self):
        ev = _ev("account lockout triggered after repeated failed login attempts")
        r = classify_event(ev)
        assert r["category"] == "account_lockout"
        assert r["confidence"] > 0

    def test_enumeration(self):
        ev = _ev("user enumeration via response timing side channel leak")
        r = classify_event(ev)
        assert r["category"] == "enumeration"
        assert r["confidence"] > 0

    def test_benign_event(self):
        ev = _ev("user logged in successfully with valid credentials")
        r = classify_event(ev)
        assert r["category"] == ""
        assert r["confidence"] == 0

    def test_empty_event(self):
        r = classify_event({})
        assert r["category"] == ""


class TestAnalyze:
    def test_empty(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["brute_events"] == 0
        assert result["risk_level"] == "none"

    def test_single_brute_event(self):
        events = [_ev("password spray across multiple accounts with common passwords")]
        result = analyze(events)
        assert result["total_events"] == 1
        assert result["brute_events"] >= 1
        assert result["risk_score"] > 0

    def test_multiple_categories(self):
        events = [
            _ev("password spray across multiple accounts"),
            _ev("dictionary attack brute force password using wordlist"),
            _ev("rate limit exceeded excessive auth attempts"),
        ]
        result = analyze(events)
        assert result["total_events"] == 3
        assert result["brute_events"] >= 2

    def test_risk_levels(self):
        critical = [_ev("password spray across multiple accounts with common passwords")] * 5
        result = analyze(critical)
        assert result["risk_level"] in ("critical", "high")

    def test_agents_tracked(self):
        events = [
            _ev("password spray across multiple accounts", agent="agent-a"),
            _ev("dictionary attack brute force password", agent="agent-b"),
        ]
        result = analyze(events)
        assert "agent-a" in result["agents_involved"]
        assert "agent-b" in result["agents_involved"]

    def test_categories_present(self):
        result = analyze([_ev("normal event")])
        cat_names = [c["category"] for c in result["categories"]]
        for cat in CATEGORIES:
            assert cat in cat_names


class TestDetectCampaigns:
    def test_campaign_detection(self):
        events = [
            _ev("password spray across multiple accounts with common passwords", agent="agent-x"),
            _ev("account lockout triggered after repeated failed login attempts", agent="agent-x"),
        ]
        campaigns = detect_campaigns(events)
        assert len(campaigns) >= 1
        assert campaigns[0].agent == "agent-x"

    def test_no_campaign_single_event(self):
        events = [_ev("password spray across multiple accounts", agent="agent-x")]
        campaigns = detect_campaigns(events)
        assert len(campaigns) == 0


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        text = format_report(result)
        assert "Brute Force Attack" in text
        assert "Total events: 0" in text

    def test_format_with_findings(self):
        events = [_ev("password spray across multiple accounts with common passwords")]
        result = analyze(events)
        text = format_report(result)
        assert "Risk score:" in text
        assert "Total events: 1" in text
