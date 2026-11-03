"""Tests for crypto_mining detection module."""

import json
import os
import tempfile

from orbit_ir.crypto_mining import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_unauthorized_miner_string(self):
        assert classify_event("xmrig detected on host") == "unauthorized_miner"

    def test_unauthorized_miner_dict(self):
        assert classify_event({"alert": "cryptominer installed"}) == "unauthorized_miner"

    def test_resource_hijack(self):
        assert classify_event("cpu spike mining detected") == "resource_hijack"

    def test_pool_connection(self):
        assert classify_event("mining pool connect to stratum") == "pool_connection"

    def test_wallet_injection(self):
        assert classify_event("wallet address replaced in clipboard") == "wallet_injection"

    def test_browser_mining(self):
        assert classify_event("coinhive detected on page") == "browser_mining"

    def test_gpu_abuse(self):
        assert classify_event("gpu mining detected on server") == "gpu_abuse"

    def test_unknown_event(self):
        assert classify_event("normal cpu usage") == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_none_input(self):
        assert classify_event(None) == "unknown"

    def test_integer_input(self):
        assert classify_event(99) == "unknown"

    def test_case_insensitive(self):
        assert classify_event("XMRIG DETECTED") == "unauthorized_miner"

    def test_dict_values_searched(self):
        assert classify_event({"type": "alert", "msg": "stratum protocol traffic"}) == "pool_connection"

    def test_hidden_miner(self):
        assert classify_event("hidden miner found in container") == "unauthorized_miner"

    def test_compute_theft(self):
        assert classify_event("compute theft via sidecar") == "resource_hijack"

    def test_hashrate_submitted(self):
        assert classify_event("hashrate submitted to pool") == "pool_connection"

    def test_clipboard_hijack(self):
        assert classify_event("clipboard hijack wallet address") == "wallet_injection"

    def test_javascript_miner(self):
        assert classify_event("javascript miner in iframe") == "browser_mining"

    def test_cuda_miner(self):
        assert classify_event("cuda miner process started") == "gpu_abuse"

    def test_coinminer_process(self):
        assert classify_event("coinminer process found") == "unauthorized_miner"

    def test_cryptojacking_script(self):
        assert classify_event("cryptojacking script loaded") == "browser_mining"

    def test_gpu_hashrate_spike(self):
        assert classify_event("gpu hashrate spike detected") == "gpu_abuse"

    def test_address_clipper(self):
        assert classify_event("address clipper malware detected") == "wallet_injection"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_no_matches(self):
        result = analyze(["normal process", "idle system"])
        assert result["flagged_count"] == 0

    def test_single_match(self):
        result = analyze(["xmrig detected"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_multiple_categories(self):
        events = ["xmrig detected", "mining pool connect", "gpu mining detected"]
        result = analyze(events)
        assert result["flagged_count"] == 3
        assert len(result["category_counts"]) == 3

    def test_high_severity(self):
        events = [f"xmrig detected {i}" for i in range(7)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [f"mining pool connect {i}" for i in range(12)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_detection_rate(self):
        events = ["xmrig detected", "normal", "coinhive detected", "normal"]
        result = analyze(events)
        assert result["detection_rate"] == 0.5

    def test_flagged_events_structure(self):
        result = analyze(["cryptominer installed"])
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "unauthorized_miner"

    def test_mixed_types(self):
        events = [{"alert": "xmrig detected"}, "coinhive detected", 42]
        result = analyze(events)
        assert result["flagged_count"] == 2

    def test_zero_detection_rate(self):
        result = analyze(["safe", "ok"])
        assert result["detection_rate"] == 0.0

    def test_dict_events(self):
        events = [{"alert": "gpu mining detected"}]
        result = analyze(events)
        assert result["flagged_count"] == 1


class TestFormatReport:
    def test_contains_title(self):
        result = analyze(["xmrig detected"])
        report = format_report(result)
        assert "Cryptocurrency Mining" in report

    def test_contains_severity(self):
        result = analyze(["coinhive detected"])
        report = format_report(result)
        assert "medium" in report

    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "0" in report

    def test_truncation(self):
        events = [f"xmrig detected {i}" for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "... and" in report


class TestLoadEvents:
    def test_load_list(self):
        data = [{"event": "xmrig detected"}, {"event": "normal"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_with_events_key(self):
        data = {"events": ["mining pool connect", "normal"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_object(self):
        data = {"event": "gpu abuse"}
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
