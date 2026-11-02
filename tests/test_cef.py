"""Tests for orbit_ir.cef."""

from __future__ import annotations

from orbit_ir.cef import finding_to_cef, findings_to_cef, _escape_header, _escape_ext_value


def _finding(**overrides: object) -> dict:
    base: dict = {
        "tool_call_id": "tc-001",
        "agent_id_transcript": "agent-0001",
        "claimed_tool": "http_get",
        "actual_tool": "shell_exec",
        "reasons": ["tool-name-mismatch"],
        "severity": "high",
        "confidence": "high",
        "control_source": "control_plane.jsonl",
        "control_line": 42,
        "finding_id": "abc123",
    }
    base.update(overrides)
    return base


def test_basic_cef_line() -> None:
    line = finding_to_cef(_finding())
    assert line.startswith("CEF:0|ORBIT|AgentIR|1.0|")
    assert "tool-name-mismatch" in line
    assert "|7|" in line  # high severity = 7
    assert "src=agent-0001" in line
    assert "cs1=tool-name-mismatch" in line
    assert "cs1Label=DetectionType" in line
    assert "cs2=control_plane.jsonl:42" in line
    assert "cs2Label=EvidenceRef" in line
    assert "cs3=abc123" in line
    assert "cs3Label=EvidenceHash" in line
    assert "claimed\\=http_get actual\\=shell_exec" in line


def test_severity_mapping() -> None:
    for sev, expected in [("critical", 10), ("high", 7), ("medium", 5), ("low", 3)]:
        line = finding_to_cef(_finding(severity=sev))
        assert f"|{expected}|" in line, f"severity={sev} should map to {expected}"


def test_escape_header_pipe() -> None:
    assert _escape_header("a|b") == "a\\|b"
    assert _escape_header("a\\b") == "a\\\\b"


def test_escape_ext_value_equals() -> None:
    assert _escape_ext_value("key=value") == "key\\=value"
    assert _escape_ext_value("a\\b") == "a\\\\b"
    assert _escape_ext_value("line1\nline2") == "line1\\nline2"


def test_special_characters_in_finding() -> None:
    f = _finding(
        agent_id_transcript="agent|with=pipe",
        effect="drop\ntable",
    )
    line = finding_to_cef(f)
    # Agent ID goes in extensions (escaped with \=, not \|)
    assert "src=agent|with\\=pipe" in line
    assert "effect\\=drop\\ntable" in line


def test_empty_findings() -> None:
    result = findings_to_cef([])
    assert result == ""


def test_multiple_findings() -> None:
    findings = [
        _finding(reasons=["tool-name-mismatch"], severity="high"),
        _finding(reasons=["unbacked-completion"], severity="medium", tool_call_id="tc-002"),
    ]
    result = findings_to_cef(findings)
    lines = result.strip().split("\n")
    assert len(lines) == 2
    assert "tool-name-mismatch" in lines[0]
    assert "unbacked-completion" in lines[1]
    assert "|7|" in lines[0]
    assert "|5|" in lines[1]


def test_missing_optional_fields() -> None:
    f = {
        "reasons": ["unknown-reason"],
        "severity": "low",
    }
    line = finding_to_cef(f)
    assert line.startswith("CEF:0|ORBIT|AgentIR|1.0|unknown-reason|")
    assert "|3|" in line
    assert "cs1=unknown-reason" in line


def test_list_source_line() -> None:
    f = _finding(control_line=[10, 20])
    line = finding_to_cef(f)
    assert "cs2=control_plane.jsonl:10" in line


def test_findings_to_cef_trailing_newline() -> None:
    result = findings_to_cef([_finding()])
    assert result.endswith("\n")
    assert result.count("\n") == 1
