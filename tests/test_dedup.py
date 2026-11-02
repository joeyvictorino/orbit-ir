from orbit_ir.dedup import deduplicate_findings, format_dedup_summary


def _finding(detection_type, agent_id, reasons=None, severity="medium", confidence_score=0.5):
    return {
        "detection_type": detection_type,
        "agent_id_transcript": agent_id,
        "reasons": reasons or [f"{detection_type}_reason"],
        "severity": severity,
        "confidence_score": confidence_score,
    }


def test_exact_dedup():
    findings = [
        _finding("spoofed_tool_call", "agent-1", ["reason_a"]),
        _finding("spoofed_tool_call", "agent-1", ["reason_a"]),
        _finding("spoofed_tool_call", "agent-1", ["reason_a"]),
    ]
    unique, removed = deduplicate_findings(findings, strategy="exact")
    assert len(unique) == 1
    assert len(removed) == 2


def test_exact_keeps_unique():
    findings = [
        _finding("spoofed_tool_call", "agent-1", ["reason_a"]),
        _finding("spoofed_tool_call", "agent-2", ["reason_a"]),
        _finding("credential_reuse", "agent-1", ["reason_b"]),
    ]
    unique, removed = deduplicate_findings(findings, strategy="exact")
    assert len(unique) == 3
    assert len(removed) == 0


def test_fuzzy_dedup():
    findings = [
        _finding("spoofed_tool_call", "agent-1", ["reason_a"]),
        _finding("spoofed_tool_call", "agent-1", ["reason_b"]),
    ]
    unique_exact, removed_exact = deduplicate_findings(findings, strategy="exact")
    assert len(unique_exact) == 2

    unique_fuzzy, removed_fuzzy = deduplicate_findings(findings, strategy="fuzzy")
    assert len(unique_fuzzy) == 1
    assert len(removed_fuzzy) == 1


def test_empty_input():
    unique, removed = deduplicate_findings([])
    assert unique == []
    assert removed == []


def test_preserves_highest_confidence():
    findings = [
        _finding("spoofed_tool_call", "agent-1", ["reason_a"], severity="low", confidence_score=0.3),
        _finding("spoofed_tool_call", "agent-1", ["reason_a"], severity="high", confidence_score=0.9),
        _finding("spoofed_tool_call", "agent-1", ["reason_a"], severity="medium", confidence_score=0.5),
    ]
    unique, removed = deduplicate_findings(findings, strategy="exact")
    assert len(unique) == 1
    assert unique[0]["severity"] == "high"
    assert unique[0]["confidence_score"] == 0.9


def test_format_summary():
    unique = [_finding("a", "b")]
    removed = [_finding("a", "b"), _finding("a", "b")]
    text = format_dedup_summary(unique, removed, "exact")
    assert "3 findings" in text
    assert "Unique:  1" in text
    assert "Removed: 2" in text
