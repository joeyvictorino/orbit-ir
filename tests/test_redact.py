"""Tests for orbit_ir.redact module."""
import json
from pathlib import Path

import pytest
from orbit_ir.redact import redact_evidence, format_redact_text


def _write_events(path: Path, events: list[dict]) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    f = path / "events.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def test_redact_emails(tmp_path):
    events = [
        {"agent_id": "a1", "message": "Contact alice@example.com for details"},
        {"agent_id": "a2", "message": "Also try bob@test.org"},
    ]
    inp = _write_events(tmp_path / "input", events)
    out = tmp_path / "output"
    result = redact_evidence(inp, out, patterns=["email"])
    assert result["redactions"] == 2
    assert result["files"] == 1
    redacted = (out / "events.jsonl").read_text().splitlines()
    assert "[EMAIL]" in redacted[0]
    assert "[EMAIL]" in redacted[1]
    assert "alice@example.com" not in redacted[0]


def test_redact_ips(tmp_path):
    events = [{"message": "Connecting to 192.168.1.100 and 10.0.0.1"}]
    inp = _write_events(tmp_path / "input", events)
    out = tmp_path / "output"
    result = redact_evidence(inp, out, patterns=["ip"])
    assert result["redactions"] == 2
    redacted = json.loads((out / "events.jsonl").read_text().strip())
    assert "[IP]" in redacted["message"]
    assert "192.168.1.100" not in redacted["message"]


def test_redact_consistent_replacement(tmp_path):
    events = [
        {"message": "user@test.com sent to user@test.com"},
        {"note": "reply from user@test.com"},
    ]
    inp = _write_events(tmp_path / "input", events)
    out = tmp_path / "output"
    result = redact_evidence(inp, out, patterns=["email"])
    lines = (out / "events.jsonl").read_text().strip().splitlines()
    obj1 = json.loads(lines[0])
    obj2 = json.loads(lines[1])
    assert "[EMAIL]" in obj1["message"]
    assert "[EMAIL]" in obj2["note"]
    assert "user@test.com" not in obj1["message"]


def test_redact_dry_run(tmp_path):
    events = [{"message": "key abc@x.com and 1.2.3.4"}]
    inp = _write_events(tmp_path / "input", events)
    out = tmp_path / "output"
    result = redact_evidence(inp, out, dry_run=True)
    assert result["dry_run"] is True
    assert result["redactions"] > 0
    assert not out.exists()


def test_redact_no_matches(tmp_path):
    events = [{"message": "nothing sensitive here"}]
    inp = _write_events(tmp_path / "input", events)
    out = tmp_path / "output"
    result = redact_evidence(inp, out, patterns=["email"])
    assert result["redactions"] == 0


def test_redact_nested_fields(tmp_path):
    events = [{"data": {"contact": "alice@example.com"}}]
    inp = _write_events(tmp_path / "input", events)
    out = tmp_path / "output"
    result = redact_evidence(inp, out, patterns=["email"])
    assert result["redactions"] == 1
    redacted = json.loads((out / "events.jsonl").read_text().strip())
    assert "[EMAIL]" in redacted["data"]["contact"]


def test_redact_list_values(tmp_path):
    events = [{"recipients": ["a@b.com", "c@d.com"]}]
    inp = _write_events(tmp_path / "input", events)
    out = tmp_path / "output"
    result = redact_evidence(inp, out, patterns=["email"])
    assert result["redactions"] == 2


def test_format_redact_text(tmp_path):
    events = [{"message": "alice@example.com"}]
    inp = _write_events(tmp_path / "input", events)
    out = tmp_path / "output"
    result = redact_evidence(inp, out, patterns=["email"])
    text = format_redact_text(result)
    assert "Redaction" in text
    assert "1" in text


def test_redact_all_patterns(tmp_path):
    events = [{"message": "email alice@x.com ip 10.0.0.1"}]
    inp = _write_events(tmp_path / "input", events)
    out = tmp_path / "output"
    result = redact_evidence(inp, out)
    assert result["redactions"] >= 2
