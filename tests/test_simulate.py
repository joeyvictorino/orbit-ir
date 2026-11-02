"""Tests for orbit_ir.simulate synthetic evidence generator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from orbit_ir.simulate import generate_evidence, list_scenarios, format_simulate_text, SCENARIOS


def test_normal_scenario(tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    result = generate_evidence(out, "normal", num_agents=3, num_events=30, seed=42)
    assert result["scenario"] == "normal"
    assert result["planted_anomalies"] == []
    assert result["num_agents"] == 3
    assert (out / "messages.jsonl").exists()
    assert (out / "transcripts.jsonl").exists()
    assert (out / "control_plane.jsonl").exists()
    assert result["total_events"] > 0


def test_tool_mismatch_scenario(tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    result = generate_evidence(out, "tool_mismatch", num_agents=3, num_events=30, seed=42)
    assert result["scenario"] == "tool_mismatch"
    assert len(result["planted_anomalies"]) > 0
    assert any("tool_mismatch" in a for a in result["planted_anomalies"])

    transcripts = _read_jsonl(out / "transcripts.jsonl")
    mismatches = [t for t in transcripts if t["claimed_tool"] != t["actual_tool"]]
    assert len(mismatches) > 0


def test_lateral_movement_scenario(tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    result = generate_evidence(out, "lateral_movement", num_agents=4, num_events=30, seed=42)
    assert any("lateral_movement" in a for a in result["planted_anomalies"])
    messages = _read_jsonl(out / "messages.jsonl")
    assert len(messages) > 10  # extra messages planted


def test_privilege_escalation_scenario(tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    result = generate_evidence(out, "privilege_escalation", num_agents=3, num_events=30, seed=42)
    assert any("privilege_escalation" in a for a in result["planted_anomalies"])


def test_data_exfiltration_scenario(tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    result = generate_evidence(out, "data_exfiltration", num_agents=3, num_events=30, seed=42)
    assert any("data_exfiltration" in a for a in result["planted_anomalies"])

    transcripts = _read_jsonl(out / "transcripts.jsonl")
    cred_reads = [t for t in transcripts if t["actual_tool"] == "credential_read"]
    assert len(cred_reads) >= 1


def test_deterministic_output(tmp_path: Path) -> None:
    out1 = tmp_path / "run1"
    out2 = tmp_path / "run2"
    r1 = generate_evidence(out1, "tool_mismatch", seed=123)
    r2 = generate_evidence(out2, "tool_mismatch", seed=123)

    msgs1 = _read_jsonl(out1 / "messages.jsonl")
    msgs2 = _read_jsonl(out2 / "messages.jsonl")
    assert msgs1 == msgs2

    tx1 = _read_jsonl(out1 / "transcripts.jsonl")
    tx2 = _read_jsonl(out2 / "transcripts.jsonl")
    assert tx1 == tx2
    assert r1["planted_anomalies"] == r2["planted_anomalies"]


def test_different_seeds(tmp_path: Path) -> None:
    out1 = tmp_path / "run1"
    out2 = tmp_path / "run2"
    generate_evidence(out1, "normal", seed=1)
    generate_evidence(out2, "normal", seed=2)

    msgs1 = _read_jsonl(out1 / "messages.jsonl")
    msgs2 = _read_jsonl(out2 / "messages.jsonl")
    assert msgs1 != msgs2


def test_custom_agents_events(tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    result = generate_evidence(out, "normal", num_agents=5, num_events=60, seed=42)
    assert result["num_agents"] == 5
    assert result["total_events"] >= 60


def test_unknown_scenario(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown scenario"):
        generate_evidence(tmp_path / "out", "not_a_scenario")


def test_list_scenarios() -> None:
    scenarios = list_scenarios()
    assert "normal" in scenarios
    assert "tool_mismatch" in scenarios
    assert "lateral_movement" in scenarios
    assert "privilege_escalation" in scenarios
    assert "data_exfiltration" in scenarios
    assert len(scenarios) == 5


def test_format_simulate_text(tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    result = generate_evidence(out, "tool_mismatch", seed=42)
    text = format_simulate_text(result)
    assert "tool_mismatch" in text
    assert "Agents:" in text
    assert "Events:" in text
    assert "Planted anomalies" in text


def test_format_simulate_text_clean(tmp_path: Path) -> None:
    out = tmp_path / "evidence"
    result = generate_evidence(out, "normal", seed=42)
    text = format_simulate_text(result)
    assert "clean scenario" in text.lower() or "No anomalies" in text


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows
