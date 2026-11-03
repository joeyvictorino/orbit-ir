"""Tests for typosquat detection module."""

import json
import os
import tempfile
import unittest

from orbit_ir.typosquat import (
    CATEGORIES,
    classify_event,
    analyze,
    detect_chains,
    load_events,
    format_report,
)


class TestClassifyEvent(unittest.TestCase):
    def test_package_misspell_typosquat(self):
        ev = {"message": "typosquat package misspelled name detected"}
        result = classify_event(ev)
        self.assertEqual(result["category"], "package_misspell")
        self.assertGreater(result["confidence"], 0)

    def test_package_misspell_lookalike(self):
        ev = {"message": "installed malicious package from homoglyph name confusion"}
        result = classify_event(ev)
        self.assertIn("package_misspell", result["indicators"])

    def test_namespace_confusion(self):
        ev = {"message": "dependency confusion namespace collision attack detected"}
        result = classify_event(ev)
        self.assertIn("namespace_confusion", result["indicators"])

    def test_namespace_public_override(self):
        ev = {"message": "public registry override shadow replace private internal package namespace confusion"}
        result = classify_event(ev)
        self.assertIn("namespace_confusion", result["indicators"])

    def test_version_pinning_remove(self):
        ev = {"message": "remove version pin from requirements to weaken constraint"}
        result = classify_event(ev)
        self.assertIn("version_pinning_remove", result["indicators"])

    def test_version_unpin(self):
        ev = {"message": "unpin version of dependency to float to latest"}
        result = classify_event(ev)
        self.assertIn("version_pinning_remove", result["indicators"])

    def test_dependency_injection(self):
        ev = {"message": "inject malicious dependency into build config package.json tamper"}
        result = classify_event(ev)
        self.assertIn("dependency_injection", result["indicators"])

    def test_dependency_backdoor(self):
        ev = {"message": "dependency backdoor trojan injected into build"}
        result = classify_event(ev)
        self.assertIn("dependency_injection", result["indicators"])

    def test_registry_spoof(self):
        ev = {"message": "registry spoof redirect to malicious mirror attack"}
        result = classify_event(ev)
        self.assertIn("registry_spoof", result["indicators"])

    def test_registry_config_tamper(self):
        ev = {"message": "npmrc tamper redirect to fake registry url endpoint"}
        result = classify_event(ev)
        self.assertIn("registry_spoof", result["indicators"])

    def test_install_script_abuse(self):
        ev = {"message": "postinstall script abuse executing malicious code during install"}
        result = classify_event(ev)
        self.assertIn("install_script_abuse", result["indicators"])

    def test_install_arbitrary_exec(self):
        ev = {"message": "arbitrary code execution during install via setup.py eval"}
        result = classify_event(ev)
        self.assertIn("install_script_abuse", result["indicators"])

    def test_no_match(self):
        ev = {"message": "normal package installation completed successfully"}
        result = classify_event(ev)
        self.assertEqual(result["category"], "")
        self.assertEqual(result["confidence"], 0)
        self.assertEqual(result["indicators"], [])

    def test_empty_event(self):
        result = classify_event({})
        self.assertEqual(result["category"], "")
        self.assertEqual(result["confidence"], 0)

    def test_multiple_indicators(self):
        ev = {"message": "typosquat package misspell then dependency confusion namespace collision"}
        result = classify_event(ev)
        self.assertGreater(len(result["indicators"]), 1)

    def test_confidence_bounded(self):
        ev = {"message": "typosquat package misspelled similar name lookalike copycat"}
        result = classify_event(ev)
        self.assertLessEqual(result["confidence"], 1.0)
        self.assertGreaterEqual(result["confidence"], 0.0)


class TestAnalyze(unittest.TestCase):
    def setUp(self):
        self.events = [
            {"agent_id": "agent1", "message": "typosquat package misspelled name", "timestamp": "2024-01-01T00:00:00Z"},
            {"agent_id": "agent1", "message": "dependency confusion namespace collision", "timestamp": "2024-01-01T00:01:00Z"},
            {"agent_id": "agent2", "message": "normal package install", "timestamp": "2024-01-01T00:02:00Z"},
            {"agent_id": "agent2", "message": "registry spoof redirect to malicious mirror", "timestamp": "2024-01-01T00:03:00Z"},
        ]

    def test_total_events(self):
        result = analyze(self.events)
        self.assertEqual(result["total_events"], 4)

    def test_squat_events_count(self):
        result = analyze(self.events)
        self.assertGreater(result["squat_events"], 0)

    def test_risk_score_bounded(self):
        result = analyze(self.events)
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 1.0)

    def test_risk_level_set(self):
        result = analyze(self.events)
        self.assertIn(result["risk_level"], ["none", "low", "medium", "high", "critical"])

    def test_categories_present(self):
        result = analyze(self.events)
        self.assertEqual(len(result["categories"]), len(CATEGORIES))

    def test_agents_involved(self):
        result = analyze(self.events)
        self.assertIn("agent1", result["agents_involved"])

    def test_empty_events(self):
        result = analyze([])
        self.assertEqual(result["total_events"], 0)
        self.assertEqual(result["squat_events"], 0)
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "none")

    def test_all_malicious_high_risk(self):
        events = [
            {"agent_id": "a1", "message": "typosquat package misspelled name"},
            {"agent_id": "a1", "message": "dependency confusion namespace collision"},
            {"agent_id": "a1", "message": "registry spoof redirect malicious mirror"},
        ]
        result = analyze(events)
        self.assertGreater(result["risk_score"], 0)

    def test_category_counts(self):
        result = analyze(self.events)
        cat_map = {c["category"]: c["count"] for c in result["categories"]}
        self.assertGreater(cat_map.get("package_misspell", 0), 0)


class TestChains(unittest.TestCase):
    def test_chain_detection(self):
        events = [
            {"agent_id": "a1", "message": "typosquat package misspelled name detected"},
            {"agent_id": "a1", "message": "dependency confusion namespace collision attack"},
            {"agent_id": "a1", "message": "install script abuse postinstall malicious code"},
        ]
        chains = detect_chains(events)
        self.assertGreater(len(chains), 0)
        chain = chains[0]
        self.assertEqual(chain.agent, "a1")
        self.assertGreater(len(chain.steps), 1)
        self.assertGreater(chain.squat_score, 0)

    def test_no_chain_single_event(self):
        events = [
            {"agent_id": "a1", "message": "typosquat package misspelled name"},
        ]
        chains = detect_chains(events)
        self.assertEqual(len(chains), 0)

    def test_chain_multiple_agents(self):
        events = [
            {"agent_id": "a1", "message": "typosquat package misspelled name detected"},
            {"agent_id": "a1", "message": "dependency confusion namespace collision"},
            {"agent_id": "a2", "message": "registry spoof redirect malicious mirror"},
            {"agent_id": "a2", "message": "install script abuse postinstall exec"},
        ]
        chains = detect_chains(events)
        agents = [c.agent for c in chains]
        self.assertIn("a1", agents)
        self.assertIn("a2", agents)

    def test_chain_score_bounded(self):
        events = [{"agent_id": "a1", "message": f"typosquat package misspell {i}"} for i in range(20)]
        chains = detect_chains(events)
        if chains:
            self.assertLessEqual(chains[0].squat_score, 1.0)

    def test_empty_events(self):
        chains = detect_chains([])
        self.assertEqual(len(chains), 0)

    def test_no_match_events(self):
        events = [
            {"agent_id": "a1", "message": "normal install"},
            {"agent_id": "a1", "message": "another normal install"},
        ]
        chains = detect_chains(events)
        self.assertEqual(len(chains), 0)


class TestLoadEvents(unittest.TestCase):
    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([{"message": "test"}], f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        self.assertEqual(len(events), 1)

    def test_load_from_directory(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "events.json")
            with open(p, "w") as f:
                json.dump([{"message": "test1"}, {"message": "test2"}], f)
            events = load_events(d)
        self.assertEqual(len(events), 2)

    def test_load_single_object(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"message": "single"}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        self.assertEqual(len(events), 1)

    def test_load_nonexistent_path(self):
        events = load_events("/nonexistent/path")
        self.assertEqual(events, [])

    def test_load_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not json{{{")
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        self.assertEqual(events, [])

    def test_load_ignores_non_json(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "readme.txt"), "w") as f:
                f.write("not json")
            events = load_events(d)
        self.assertEqual(events, [])


class TestFormat(unittest.TestCase):
    def test_format_empty(self):
        result = analyze([])
        text = format_report(result)
        self.assertIn("Typosquatting", text)
        self.assertIn("Total events: 0", text)

    def test_format_with_events(self):
        events = [
            {"agent_id": "a1", "message": "typosquat package misspelled name detected"},
            {"agent_id": "a1", "message": "dependency confusion namespace collision"},
        ]
        result = analyze(events)
        text = format_report(result)
        self.assertIn("Typosquatting", text)
        self.assertIn("package_misspell", text)

    def test_format_with_chains(self):
        events = [
            {"agent_id": "a1", "message": "typosquat package misspelled name detected"},
            {"agent_id": "a1", "message": "dependency confusion namespace collision"},
            {"agent_id": "a1", "message": "install script abuse postinstall exec"},
        ]
        result = analyze(events)
        text = format_report(result)
        self.assertIn("Typosquat chains", text)
        self.assertIn("a1", text)

    def test_format_risk_info(self):
        events = [{"agent_id": "a1", "message": "typosquat package misspelled name"}]
        result = analyze(events)
        text = format_report(result)
        self.assertIn("Risk score", text)


if __name__ == "__main__":
    unittest.main()
