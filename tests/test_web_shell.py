"""Tests for web_shell detection module."""

from orbit_ir.web_shell import analyze, classify_event, detect_chains, format_report, CATEGORIES


def _ev(msg, agent="agent-1", **kw):
    d = {"message": msg, "agent_id": agent, "timestamp": "2025-01-01T00:00:00Z"}
    d.update(kw)
    return d


class TestClassifyEvent:
    def test_webshell_upload(self):
        ev = _ev("upload web shell to public htdocs directory")
        r = classify_event(ev)
        assert r["category"] == "webshell_upload"
        assert r["confidence"] > 0

    def test_webshell_execution(self):
        ev = _ev("web shell exec command via http endpoint")
        r = classify_event(ev)
        assert r["category"] == "webshell_execution"
        assert r["confidence"] > 0

    def test_webshell_obfuscation(self):
        ev = _ev("obfuscated web shell code with encoded payload")
        r = classify_event(ev)
        assert r["category"] == "webshell_obfuscation"
        assert r["confidence"] > 0

    def test_reverse_shell(self):
        ev = _ev("reverse shell establish connection callback to attacker")
        r = classify_event(ev)
        assert r["category"] == "reverse_shell"
        assert r["confidence"] > 0

    def test_file_manager_abuse(self):
        ev = _ev("file manager exploit abuse unauthorized access to server files")
        r = classify_event(ev)
        assert r["category"] == "file_manager_abuse"
        assert r["confidence"] > 0

    def test_backdoor_persistence(self):
        ev = _ev("plant hidden backdoor endpoint created in web app")
        r = classify_event(ev)
        assert r["category"] == "backdoor_persistence"
        assert r["confidence"] > 0

    def test_benign_event(self):
        ev = _ev("normal web page load completed successfully")
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
        assert result["shell_events"] == 0
        assert result["risk_level"] == "none"

    def test_single_shell_event(self):
        events = [_ev("upload web shell to public htdocs directory")]
        result = analyze(events)
        assert result["total_events"] == 1
        assert result["shell_events"] >= 1
        assert result["risk_score"] > 0

    def test_multiple_categories(self):
        events = [
            _ev("upload web shell to public htdocs directory"),
            _ev("reverse shell establish connection callback"),
            _ev("plant backdoor persistent endpoint in web app"),
        ]
        result = analyze(events)
        assert result["total_events"] == 3
        assert result["shell_events"] >= 2

    def test_risk_levels(self):
        critical = [_ev("upload web shell to public htdocs")] * 5
        result = analyze(critical)
        assert result["risk_level"] in ("critical", "high")

    def test_agents_tracked(self):
        events = [
            _ev("upload web shell to htdocs", agent="agent-a"),
            _ev("reverse shell establish connection", agent="agent-b"),
        ]
        result = analyze(events)
        assert "agent-a" in result["agents_involved"]
        assert "agent-b" in result["agents_involved"]

    def test_categories_present(self):
        result = analyze([_ev("normal event")])
        cat_names = [c["category"] for c in result["categories"]]
        for cat in CATEGORIES:
            assert cat in cat_names


class TestDetectChains:
    def test_chain_detection(self):
        events = [
            _ev("upload web shell to public htdocs", agent="agent-x"),
            _ev("reverse shell establish connection callback", agent="agent-x"),
        ]
        chains = detect_chains(events)
        assert len(chains) >= 1
        assert chains[0].agent == "agent-x"

    def test_no_chain_single_event(self):
        events = [_ev("upload web shell to public htdocs", agent="agent-x")]
        chains = detect_chains(events)
        assert len(chains) == 0


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        text = format_report(result)
        assert "Web Shell Detection" in text
        assert "Total events: 0" in text

    def test_format_with_findings(self):
        events = [_ev("upload web shell to public htdocs directory")]
        result = analyze(events)
        text = format_report(result)
        assert "Risk score:" in text
        assert "Total events: 1" in text
