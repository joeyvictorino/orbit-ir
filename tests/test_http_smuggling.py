"""Tests for http_smuggling detection module."""

import json

import pytest

from orbit_ir.http_smuggling import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


class TestClassifyEvent:
    def test_cl_te_desync_headers(self):
        event = {"content_length": "42", "transfer_encoding": "identity"}
        assert classify_event(event) == "cl_te_desync"

    def test_te_cl_desync_chunked(self):
        event = {"content_length": "42", "transfer_encoding": "chunked"}
        assert classify_event(event) == "te_cl_desync"

    def test_cl_te_keyword(self):
        event = {"description": "CL.TE desync: content-length mismatch in proxy layer"}
        assert classify_event(event) == "cl_te_desync"

    def test_te_cl_keyword(self):
        event = {"description": "TE-CL desync chunked content-length mismatch"}
        assert classify_event(event) == "te_cl_desync"

    def test_te_te_obfuscation(self):
        event = {"description": "Transfer-Encoding header obfuscation with xchunked"}
        assert classify_event(event) == "te_te_obfuscation"

    def test_request_splitting_crlf(self):
        event = {"description": "CRLF injection in HTTP header allows request splitting"}
        assert classify_event(event) == "request_splitting"

    def test_h2c_smuggling(self):
        event = {"description": "H2C smuggling via Upgrade: h2c header"}
        assert classify_event(event) == "h2c_smuggling"

    def test_websocket_smuggling(self):
        event = {"description": "WebSocket smuggling via Upgrade: websocket tunnel"}
        assert classify_event(event) == "websocket_smuggling"

    def test_h2c_takes_priority_over_splitting(self):
        event = {"description": "H2C smuggling with CRLF injection"}
        assert classify_event(event) == "h2c_smuggling"

    def test_ws_takes_priority_over_te(self):
        event = {"description": "WebSocket smuggling TE.TE obfuscation"}
        assert classify_event(event) == "websocket_smuggling"

    def test_te_te_dual_encoding(self):
        event = {"description": "TE.TE detected with malformed chunked encoding mutation"}
        assert classify_event(event) == "te_te_obfuscation"

    def test_http_desync_keyword(self):
        event = {"description": "HTTP desync attack via request boundary confusion"}
        assert classify_event(event) == "request_splitting"

    def test_smuggled_request(self):
        event = {"description": "Smuggled request with prefix injection and request boundary"}
        assert classify_event(event) == "request_splitting"

    def test_content_length_mismatch(self):
        event = {"description": "Content-Length mismatch between front and backend"}
        assert classify_event(event) == "cl_te_desync"

    def test_cleartext_http2(self):
        event = {"description": "Cleartext HTTP2 upgrade detected in proxy"}
        assert classify_event(event) == "h2c_smuggling"

    def test_fallback_to_cl_te(self):
        event = {"description": "ambiguous content-length mismatch parsing detected"}
        assert classify_event(event) == "cl_te_desync"

    def test_encoding_precedence(self):
        event = {"description": "Encoding precedence issue: chunked content-length mismatch"}
        assert classify_event(event) == "te_cl_desync"


class TestAnalyze:
    def test_empty_events(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["smuggling_events"] == 0
        assert result["severity"] == "none"

    def test_single_event(self):
        events = [{"description": "CL-TE desync", "id": "1"}]
        result = analyze(events)
        assert result["smuggling_events"] == 1
        assert result["severity"] == "low"

    def test_medium_severity(self):
        events = [{"description": f"CL-TE desync #{i}", "id": str(i)} for i in range(4)]
        result = analyze(events)
        assert result["severity"] == "medium"

    def test_high_severity(self):
        events = [{"description": f"CL-TE desync #{i}", "id": str(i)} for i in range(8)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_critical_severity(self):
        events = [{"description": f"CL-TE desync #{i}", "id": str(i)} for i in range(15)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_mixed_categories(self):
        events = [
            {"description": "H2C smuggling attempt", "id": "1"},
            {"description": "WebSocket smuggling via ws tunnel", "id": "2"},
            {"description": "CRLF injection request splitting", "id": "3"},
        ]
        result = analyze(events)
        assert result["categories"]["h2c_smuggling"] >= 1
        assert result["categories"]["websocket_smuggling"] >= 1
        assert result["categories"]["request_splitting"] >= 1

    def test_findings_have_fields(self):
        events = [{"content_length": "100", "transfer_encoding": "chunked", "id": "evt-1"}]
        result = analyze(events)
        f = result["findings"][0]
        assert f["event_id"] == "evt-1"
        assert f["content_length"] == "100"
        assert f["transfer_encoding"] == "chunked"

    def test_findings_unknown_id(self):
        events = [{"description": "CL-TE desync"}]
        result = analyze(events)
        assert result["findings"][0]["event_id"] == "unknown"


class TestFormatReport:
    def test_empty_report(self):
        result = analyze([])
        report = format_report(result)
        assert "HTTP Request Smuggling" in report
        assert "none" in report

    def test_report_contains_findings(self):
        events = [{"description": "H2C smuggling", "id": "1"}]
        result = analyze(events)
        report = format_report(result)
        assert "h2c_smuggling" in report

    def test_report_severity(self):
        events = [{"description": f"CL-TE #{i}", "id": str(i)} for i in range(15)]
        result = analyze(events)
        report = format_report(result)
        assert "critical" in report

    def test_report_category_breakdown(self):
        events = [
            {"description": "H2C smuggling", "id": "1"},
            {"description": "WebSocket smuggling via ws tunnel", "id": "2"},
        ]
        result = analyze(events)
        report = format_report(result)
        assert "h2c_smuggling" in report
        assert "websocket_smuggling" in report


class TestLoadEvents:
    def test_load_json_array(self, tmp_path):
        data = [{"content_length": "10", "transfer_encoding": "chunked"}]
        p = tmp_path / "events.json"
        p.write_text(json.dumps(data))
        events = load_events(str(p))
        assert len(events) == 1

    def test_load_ndjson(self, tmp_path):
        lines = ['{"id": "1"}', '{"id": "2"}']
        p = tmp_path / "events.ndjson"
        p.write_text("\n".join(lines))
        events = load_events(str(p))
        assert len(events) == 2

    def test_empty_lines_skipped(self, tmp_path):
        p = tmp_path / "events.ndjson"
        p.write_text('{"x":1}\n\n{"x":2}\n')
        events = load_events(str(p))
        assert len(events) == 2
