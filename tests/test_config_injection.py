"""Tests for config_injection detection module."""

import json
import os
import tempfile

from orbit_ir.config_injection import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_env_injection_string(self):
        assert classify_event("env injection detected in container") == "env_injection"

    def test_env_injection_dict(self):
        assert classify_event({"action": "ld_preload inject attempt"}) == "env_injection"

    def test_config_tamper(self):
        assert classify_event("config file modified by attacker") == "config_tamper"

    def test_parameter_poison(self):
        assert classify_event("runtime parameter inject detected") == "parameter_poison"

    def test_feature_flag(self):
        assert classify_event("feature flag manipulation in prod") == "feature_flag"

    def test_settings_override(self):
        assert classify_event("settings override escalation found") == "settings_override"

    def test_deploy_config(self):
        assert classify_event("helm values inject in cluster") == "deploy_config"

    def test_unknown_event(self):
        assert classify_event("normal config update") == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_none_input(self):
        assert classify_event(None) == "unknown"

    def test_integer_input(self):
        assert classify_event(42) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("ENV INJECTION ATTACK") == "env_injection"

    def test_dict_values_searched(self):
        assert classify_event({"type": "alert", "detail": "yaml injection payload"}) == "config_tamper"

    def test_env_path_injection(self):
        assert classify_event("env path injection via service") == "env_injection"

    def test_config_overwrite(self):
        assert classify_event("config overwrite detected") == "config_tamper"

    def test_cli_argument_inject(self):
        assert classify_event("cli argument inject in startup") == "parameter_poison"

    def test_feature_gate_bypass(self):
        assert classify_event("feature gate bypass attempt") == "feature_flag"

    def test_global_config_override(self):
        assert classify_event("global config override applied") == "settings_override"

    def test_terraform_config_poison(self):
        assert classify_event("terraform config poison in plan") == "deploy_config"

    def test_library_path_inject(self):
        assert classify_event("library path inject via env") == "env_injection"

    def test_json_config_poison(self):
        assert classify_event("json config poison detected") == "config_tamper"

    def test_argument_smuggling(self):
        assert classify_event("argument smuggling in cmd") == "parameter_poison"

    def test_pipeline_config_tamper(self):
        assert classify_event("ci/cd config inject in pipeline") == "deploy_config"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_no_matches(self):
        result = analyze(["normal event", "another normal event"])
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        result = analyze(["env injection detected"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"
        assert result["category_counts"]["env_injection"] == 1

    def test_multiple_categories(self):
        events = ["env injection", "config tamper", "deploy config"]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"env injection event {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"config tamper event {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["env injection", "normal", "config tamper", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_events_structure(self):
        result = analyze(["feature flag manipulation"])
        assert len(result["flagged_events"]) == 1
        entry = result["flagged_events"][0]
        assert "index" in entry
        assert "category" in entry
        assert "event" in entry

    def test_mixed_types(self):
        events = [{"action": "env injection"}, "config tamper detected", 42]
        result = analyze(events)
        assert result["flagged_count"] == 2

    def test_all_unknown(self):
        result = analyze(["safe", "okay", "fine"])
        assert result["flagged_count"] == 0
        assert result["detection_rate"] == 0.0

    def test_dict_events(self):
        events = [{"alert": "terraform config poison found"}]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_contains_title(self):
        result = analyze(["env injection found"])
        report = format_report(result)
        assert "Configuration Injection" in report

    def test_contains_severity(self):
        result = analyze(["config tamper detected"])
        report = format_report(result)
        assert "medium" in report

    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "0" in report

    def test_truncation(self):
        events = [f"env injection event {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report


class TestLoadEvents:
    def test_load_list(self):
        data = [{"event": "env injection"}, {"event": "normal"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_with_events_key(self):
        data = {"events": ["config tamper", "normal"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_object(self):
        data = {"event": "feature flag manipulation"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1


class TestCategories:
    def test_all_categories_have_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) >= 5, f"{cat} has fewer than 5 indicators"

    def test_category_count(self):
        assert len(CATEGORIES) == 6
