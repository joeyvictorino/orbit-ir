"""Tests for protocol abuse detection module."""

import os
import tempfile

from orbit_ir.protocol_abuse import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_dns_tunneling(self):
        assert classify_event("unusually long dns query detected") == "dns_tunneling"

    def test_http_smuggling(self):
        assert classify_event("content-length transfer-encoding mismatch found") == "http_smuggling"

    def test_protocol_downgrade(self):
        assert classify_event("tls downgrade to ssl detected") == "protocol_downgrade"

    def test_websocket_abuse(self):
        assert classify_event("websocket origin bypass attempt") == "websocket_abuse"

    def test_grpc_manipulation(self):
        assert classify_event("grpc metadata injection found") == "grpc_manipulation"

    def test_icmp_covert(self):
        assert classify_event("icmp payload with encoded data detected") == "icmp_covert"

    def test_uncategorized(self):
        assert classify_event("normal network traffic") == "uncategorized"

    def test_case_insensitive(self):
        assert classify_event("UNUSUALLY LONG DNS QUERY") == "dns_tunneling"

    def test_empty_string(self):
        assert classify_event("") == "uncategorized"

    def test_partial_match(self):
        assert classify_event("found chunked encoding manipulation in request") == "http_smuggling"

    def test_single_match(self):
        assert classify_event("grpc channel without tls configured") == "grpc_manipulation"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["categorized"] == 0
        assert result["title"] == "Protocol Abuse Detection Report"

    def test_single_event(self):
        result = analyze(["unusually long dns query found"])
        assert result["total_events"] == 1
        assert result["categorized"] == 1
        assert result["uncategorized"] == 0

    def test_multiple_categories(self):
        events = [
            "unusually long dns query found",
            "content-length transfer-encoding mismatch",
            "tls downgrade to ssl detected",
            "websocket origin bypass",
            "grpc metadata injection",
            "icmp payload with encoded data",
        ]
        result = analyze(events)
        assert result["total_events"] == 6
        assert result["categorized"] == 6
        cats = set(r["category"] for r in result["results"])
        assert len(cats) == 6

    def test_uncategorized_events(self):
        result = analyze(["normal traffic", "regular operation"])
        assert result["uncategorized"] == 2

    def test_category_counts(self):
        events = [
            "unusually long dns query",
            "encoded data in dns subdomain",
            "content-length transfer-encoding mismatch",
        ]
        result = analyze(events)
        assert result["category_counts"]["dns_tunneling"] == 2
        assert result["category_counts"]["http_smuggling"] == 1

    def test_mixed_events(self):
        events = ["unusually long dns query", "normal traffic"]
        result = analyze(events)
        assert result["categorized"] == 1
        assert result["uncategorized"] == 1

    def test_results_structure(self):
        result = analyze(["tls downgrade to ssl"])
        assert len(result["results"]) == 1
        assert "event" in result["results"][0]
        assert "category" in result["results"][0]

    def test_all_uncategorized(self):
        result = analyze(["nothing", "nada", "zilch"])
        assert result["categorized"] == 0
        assert result["uncategorized"] == 3

    def test_duplicate_events(self):
        result = analyze(["tls downgrade to ssl"] * 3)
        assert result["total_events"] == 3
        assert result["category_counts"]["protocol_downgrade"] == 3


class TestFormatReport:
    def test_format_has_title(self):
        result = analyze(["unusually long dns query"])
        report = format_report(result)
        assert "Protocol Abuse Detection Report" in report

    def test_format_has_counts(self):
        result = analyze(["unusually long dns query", "normal traffic"])
        report = format_report(result)
        assert "Total events: 2" in report
        assert "Categorized: 1" in report

    def test_format_has_details(self):
        result = analyze(["tls downgrade to ssl"])
        report = format_report(result)
        assert "[protocol_downgrade]" in report

    def test_format_empty(self):
        result = analyze([])
        report = format_report(result)
        assert "Total events: 0" in report


class TestLoadEvents:
    def test_load_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("unusually long dns query\n")
            f.write("content-length transfer-encoding mismatch\n")
            f.write("\n")
            f.write("normal traffic\n")
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 3
            assert events[0] == "unusually long dns query"
        finally:
            os.unlink(path)

    def test_load_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("")
            path = f.name
        try:
            events = load_events(path)
            assert len(events) == 0
        finally:
            os.unlink(path)

    def test_load_strips_whitespace(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("  unusually long dns query  \n")
            path = f.name
        try:
            events = load_events(path)
            assert events[0] == "unusually long dns query"
        finally:
            os.unlink(path)


class TestCategories:
    def test_all_categories_have_indicators(self):
        for cat, indicators in CATEGORIES.items():
            assert len(indicators) == 10, f"{cat} has {len(indicators)} indicators"

    def test_six_categories(self):
        assert len(CATEGORIES) == 6
