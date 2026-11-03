"""Tests for cryptojacking detection module."""

import json
import os
import tempfile

import pytest

from orbit_ir.cryptojacking import CATEGORIES, classify_event, analyze, format_report, load_events


class TestClassifyEvent:
    def test_mining_pool(self):
        assert classify_event("Connection to mining pool detected") == "mining_pool"

    def test_stratum_protocol(self):
        assert classify_event("Stratum protocol traffic on port 3333") == "mining_pool"

    def test_nicehash(self):
        assert classify_event("Traffic to nicehash servers detected") == "mining_pool"

    def test_cpu_abuse(self):
        assert classify_event("CPU mining process consuming all cores") == "cpu_abuse"

    def test_xmrig(self):
        assert classify_event("XMRig binary detected in container") == "cpu_abuse"

    def test_cryptonight(self):
        assert classify_event("CryptoNight algorithm running on host") == "cpu_abuse"

    def test_randomx(self):
        assert classify_event("RandomX hash computation detected") == "cpu_abuse"

    def test_gpu_abuse(self):
        assert classify_event("GPU mining detected on CUDA devices") == "gpu_abuse"

    def test_ethash(self):
        assert classify_event("Ethash computation consuming GPU resources") == "gpu_abuse"

    def test_browser_mining(self):
        assert classify_event("Browser mining script loaded on page") == "browser_mining"

    def test_coinhive_script(self):
        assert classify_event("Browser mining coinhive script injected") == "browser_mining"

    def test_wasm_miner(self):
        assert classify_event("WASM miner loaded in browser tab") == "browser_mining"

    def test_container_mining(self):
        assert classify_event("Container mining detected in Kubernetes pod") == "container_mining"

    def test_docker_miner(self):
        assert classify_event("Docker miner image pulled and running") == "container_mining"

    def test_pod_mining(self):
        assert classify_event("Pod mining resources hijacked") == "container_mining"

    def test_wallet_activity(self):
        assert classify_event("Mining wallet received payout") == "wallet_activity"

    def test_monero_wallet(self):
        assert classify_event("Monero wallet address in config file") == "wallet_activity"

    def test_unknown(self):
        assert classify_event("Normal application log entry") == "unknown"

    def test_none_event(self):
        assert classify_event(None) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_whitespace_only(self):
        assert classify_event("   \t  ") == "unknown"

    def test_dict_event(self):
        assert classify_event({"alert": "xmrig process started"}) == "cpu_abuse"

    def test_case_insensitive(self):
        assert classify_event("MINING POOL connection established") == "mining_pool"

    def test_non_string_non_dict(self):
        assert classify_event(3.14) == "unknown"

    def test_f2pool(self):
        assert classify_event("Connections to f2pool detected") == "mining_pool"


class TestAnalyze:
    def test_empty(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"
        assert result["detection_rate"] == 0.0

    def test_single_match(self):
        result = analyze(["xmrig detected on server"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_no_matches(self):
        result = analyze(["regular http request", "database query"])
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_severity_high(self):
        events = [f"mining pool connection #{i}" for i in range(6)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = [f"xmrig instance #{i}" for i in range(11)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_category_counts(self):
        events = ["xmrig detected", "mining pool connection", "gpu mining started"]
        result = analyze(events)
        assert result["category_counts"]["cpu_abuse"] == 1
        assert result["category_counts"]["mining_pool"] == 1
        assert result["category_counts"]["gpu_abuse"] == 1

    def test_detection_rate(self):
        events = ["xmrig", "normal event", "normal event 2"]
        result = analyze(events)
        assert abs(result["detection_rate"] - 1/3) < 0.01

    def test_flagged_structure(self):
        result = analyze(["docker miner found"])
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "container_mining"
        assert entry["event"] == "docker miner found"


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        text = format_report(result)
        assert "Cryptojacking Detection Report" in text
        assert "Severity:          none" in text

    def test_format_with_findings(self):
        result = analyze(["xmrig binary", "mining pool traffic"])
        text = format_report(result)
        assert "Flagged:           2" in text
        assert "cpu_abuse" in text

    def test_format_truncation(self):
        events = [f"mining pool connection #{i}" for i in range(15)]
        result = analyze(events)
        text = format_report(result)
        assert "... and 5 more" in text

    def test_format_detection_rate(self):
        result = analyze(["xmrig", "normal"])
        text = format_report(result)
        assert "50.0%" in text


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["event1", "event2"], f)
            path = f.name
        try:
            assert load_events(path) == ["event1", "event2"]
        finally:
            os.unlink(path)

    def test_load_dict_with_events_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": ["a", "b"]}, f)
            path = f.name
        try:
            assert load_events(path) == ["a", "b"]
        finally:
            os.unlink(path)

    def test_load_single_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"type": "mining"}, f)
            path = f.name
        try:
            assert load_events(path) == [{"type": "mining"}]
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_have_patterns(self):
        for cat, patterns in CATEGORIES.items():
            assert len(patterns) >= 5, f"{cat} has too few patterns"

    def test_category_names(self):
        expected = {"mining_pool", "cpu_abuse", "gpu_abuse", "browser_mining",
                    "container_mining", "wallet_activity"}
        assert set(CATEGORIES.keys()) == expected
