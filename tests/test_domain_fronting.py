"""Tests for domain_fronting detection module."""

import json
import os
import tempfile

import pytest

from orbit_ir.domain_fronting import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_sni_host_mismatch_explicit(self):
        event = {"sni": "innocent.com", "host": "evil.com"}
        assert classify_event(event) == "sni_host_mismatch"

    def test_cdn_abuse_cloudfront(self):
        event = {"sni": "d12345.cloudfront.net", "host": "malware-c2.com"}
        assert classify_event(event) == "cloud_fronting"

    def test_cdn_abuse_akamai(self):
        event = {"sni": "akamai-cdn.example.com", "host": "evil.com"}
        assert classify_event(event) == "cdn_abuse"

    def test_cloud_fronting_azure(self):
        event = {"sni": "legit.azureedge.net", "host": "c2-server.com"}
        assert classify_event(event) == "cloud_fronting"

    def test_cloud_fronting_appspot(self):
        event = {"sni": "app.appspot.com", "host": "hidden-domain.com"}
        assert classify_event(event) == "cloud_fronting"

    def test_cloud_fronting_by_keyword(self):
        event = {"description": "Cloud fronting detected via Azure endpoint"}
        assert classify_event(event) == "cloud_fronting"

    def test_tls_header_discrepancy(self):
        event = {"description": "TLS SNI field does not match HTTP host, handshake domain mismatch"}
        assert classify_event(event) == "tls_header_discrepancy"

    def test_nested_tunnel(self):
        event = {"description": "Nested tunnel detected within domain-fronted connection"}
        assert classify_event(event) == "nested_tunnel"

    def test_fronting_chain_multi_hop(self):
        event = {"description": "Multi-hop fronting chain through three CDN providers"}
        assert classify_event(event) == "fronting_chain"

    def test_cdn_abuse_keyword(self):
        event = {"description": "CDN relay used to forward covert traffic"}
        assert classify_event(event) == "cdn_abuse"

    def test_sni_mismatch_keyword(self):
        event = {"description": "SNI mismatch detected in outbound request"}
        assert classify_event(event) == "sni_host_mismatch"

    def test_matching_sni_host_still_classifies(self):
        event = {"sni": "same.com", "host": "same.com", "description": "fronted request observed"}
        assert classify_event(event) == "sni_host_mismatch"

    def test_host_header_field(self):
        event = {"sni": "legit.com", "host_header": "evil.com"}
        assert classify_event(event) == "sni_host_mismatch"

    def test_cloud_fronting_amazonaws(self):
        event = {"sni": "bucket.s3.amazonaws.com", "host": "c2.badguy.com"}
        assert classify_event(event) == "cloud_fronting"

    def test_empty_sni_falls_through(self):
        event = {"sni": "", "host": "evil.com", "description": "domain fronting attempt"}
        assert classify_event(event) == "sni_host_mismatch"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["domain_fronting_events"] == 0
        assert result["severity"] == "none"

    def test_single_event(self):
        events = [{"sni": "good.com", "host": "bad.com", "id": "1"}]
        result = analyze(events)
        assert result["domain_fronting_events"] == 1
        assert result["severity"] == "low"
        assert len(result["findings"]) == 1

    def test_medium_severity(self):
        events = [{"sni": f"good{i}.com", "host": "bad.com", "id": str(i)} for i in range(4)]
        result = analyze(events)
        assert result["severity"] == "medium"

    def test_high_severity(self):
        events = [{"sni": f"sni{i}.com", "host": "c2.com", "id": str(i)} for i in range(8)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [{"sni": f"sni{i}.com", "host": "c2.com", "id": str(i)} for i in range(15)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_categories_counted(self):
        events = [
            {"sni": "a.cloudfront.net", "host": "evil.com", "id": "1"},
            {"sni": "b.com", "host": "c.com", "id": "2"},
        ]
        result = analyze(events)
        assert result["categories"]["cloud_fronting"] >= 1
        assert result["categories"]["sni_host_mismatch"] >= 1

    def test_findings_have_event_id(self):
        events = [{"sni": "a.com", "host": "b.com", "event_id": "evt-123"}]
        result = analyze(events)
        assert result["findings"][0]["event_id"] == "evt-123"

    def test_findings_unknown_id(self):
        events = [{"sni": "a.com", "host": "b.com"}]
        result = analyze(events)
        assert result["findings"][0]["event_id"] == "unknown"


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "Domain Fronting" in report
        assert "none" in report

    def test_report_contains_findings(self):
        events = [{"sni": "good.com", "host": "bad.com", "id": "1"}]
        result = analyze(events)
        report = format_report(result)
        assert "sni_host_mismatch" in report
        assert "good.com" in report

    def test_report_shows_severity(self):
        events = [{"sni": f"s{i}.com", "host": "c2.com", "id": str(i)} for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "critical" in report


class TestLoadEvents:
    def test_load_json_array(self, tmp_path):
        data = [{"sni": "a.com", "host": "b.com"}]
        p = tmp_path / "events.json"
        p.write_text(json.dumps(data))
        events = load_events(str(p))
        assert len(events) == 1

    def test_load_ndjson(self, tmp_path):
        lines = ['{"sni": "a.com", "host": "b.com"}', '{"sni": "c.com", "host": "d.com"}']
        p = tmp_path / "events.ndjson"
        p.write_text("\n".join(lines))
        events = load_events(str(p))
        assert len(events) == 2

    def test_load_empty_lines_skipped(self, tmp_path):
        content = '{"x": 1}\n\n{"x": 2}\n'
        p = tmp_path / "events.ndjson"
        p.write_text(content)
        events = load_events(str(p))
        assert len(events) == 2
