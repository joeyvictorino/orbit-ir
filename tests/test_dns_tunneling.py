import json
import os
import tempfile
import pytest
from orbit_ir.dns_tunneling import classify_event, analyze, format_report, load_events, CATEGORIES


class TestClassifyEvent:
    def test_dns_tunneling(self):
        assert classify_event("Detected dns tunneling activity") == "dns_exfiltration"

    def test_dns_exfiltration(self):
        assert classify_event("dns exfiltration detected in traffic") == "dns_exfiltration"

    def test_base64_dns(self):
        assert classify_event("base64 dns encoded payload found") == "dns_exfiltration"

    def test_dns_c2_channel(self):
        assert classify_event("dns c2 channel established") == "dns_c2"

    def test_dns_beacon(self):
        assert classify_event("periodic dns beacon detected") == "dns_c2"

    def test_dns_polling(self):
        assert classify_event("dns polling for command updates") == "dns_c2"

    def test_unusual_dns_query(self):
        assert classify_event("unusual dns query pattern observed") == "unusual_query"

    def test_dga_domain(self):
        assert classify_event("dga domain generation detected") == "unusual_query"

    def test_excessive_nxdomain(self):
        assert classify_event("excessive nxdomain responses observed") == "unusual_query"

    def test_dns_amplification(self):
        assert classify_event("dns amplification attack detected") == "protocol_abuse"

    def test_dns_rebinding(self):
        assert classify_event("dns rebinding attempt found") == "protocol_abuse"

    def test_axfr_query(self):
        assert classify_event("unauthorized axfr query detected") == "protocol_abuse"

    def test_iodine_tunnel(self):
        assert classify_event("iodine tunnel traffic observed") == "tunnel_tool"

    def test_dnscat(self):
        assert classify_event("dnscat session initiated") == "tunnel_tool"

    def test_cobalt_strike_dns(self):
        assert classify_event("cobalt strike dns channel active") == "tunnel_tool"

    def test_cname_tunneling(self):
        assert classify_event("cname tunneling detected in queries") == "record_abuse"

    def test_mx_record_exfil(self):
        assert classify_event("mx record exfil data transfer") == "record_abuse"

    def test_unknown(self):
        assert classify_event("normal web traffic") == "unknown"

    def test_none_event(self):
        assert classify_event(None) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_whitespace_only(self):
        assert classify_event("   ") == "unknown"

    def test_dict_event(self):
        assert classify_event({"action": "dns tunneling detected"}) == "dns_exfiltration"

    def test_case_insensitive(self):
        assert classify_event("DNS TUNNELING Detected") == "dns_exfiltration"

    def test_non_string_non_dict(self):
        assert classify_event(42) == "unknown"


class TestAnalyze:
    def test_empty(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        result = analyze(["dns tunneling detected"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_no_matches(self):
        result = analyze(["normal traffic", "safe query"])
        assert result["flagged_count"] == 0

    def test_severity_high(self):
        events = [f"dns tunneling event {i}" for i in range(6)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = [f"dns tunneling event {i}" for i in range(11)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_category_counts(self):
        events = ["dns tunneling detected", "dns c2 channel found", "dns tunneling again"]
        result = analyze(events)
        assert result["category_counts"]["dns_exfiltration"] == 2
        assert result["category_counts"]["dns_c2"] == 1

    def test_detection_rate(self):
        result = analyze(["dns tunneling", "normal", "dns c2 channel", "safe"])
        assert result["detection_rate"] == 0.5

    def test_flagged_structure(self):
        result = analyze(["dns tunneling activity"])
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "dns_exfiltration"
        assert entry["event"] == "dns tunneling activity"


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        text = format_report(result)
        assert "DNS Tunneling" in text

    def test_format_with_findings(self):
        result = analyze(["dns tunneling activity"])
        text = format_report(result)
        assert "dns_exfiltration" in text

    def test_format_truncation(self):
        events = [f"dns tunneling event {i}" for i in range(15)]
        result = analyze(events)
        text = format_report(result)
        assert "... and 5 more" in text

    def test_format_detection_rate(self):
        result = analyze(["dns tunneling", "normal"])
        text = format_report(result)
        assert "50.0%" in text


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["event1", "event2"], f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_dict_with_events_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": ["a", "b"]}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"action": "test"}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1


class TestCategories:
    def test_all_categories_have_patterns(self):
        for cat, patterns in CATEGORIES.items():
            assert len(patterns) > 0, f"category {cat} has no patterns"

    def test_category_names(self):
        expected = {"dns_exfiltration", "dns_c2", "unusual_query", "protocol_abuse", "tunnel_tool", "record_abuse"}
        assert set(CATEGORIES.keys()) == expected
