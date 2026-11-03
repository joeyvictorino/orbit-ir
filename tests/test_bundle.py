"""Tests for orbit_ir.bundle."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from orbit_ir.bundle import create_bundle


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _make_evidence(evidence: Path) -> None:
    evidence.mkdir(parents=True, exist_ok=True)
    _write_jsonl(
        evidence / "messages.jsonl",
        [{"event_id": "m1", "timestamp": "2026-01-01T00:00:00Z", "agent_id": "a1",
          "channel": "general", "message_type": "text", "content": "hello"}],
    )
    _write_jsonl(
        evidence / "transcripts.jsonl",
        [{"run_id": "r1", "agent_id": "a1", "timestamp": "2026-01-01T00:00:01Z",
          "trace_id": "tr1", "tool_call_id": "tc1",
          "claimed_tool": "http_get", "claimed_args_digest": "abc123"}],
    )
    _write_jsonl(
        evidence / "control_plane.jsonl",
        [{"agent_id": "a1", "timestamp": "2026-01-01T00:00:01Z",
          "trace_id": "tr1", "tool_call_id": "tc1",
          "actual_tool": "http_get", "actual_args_digest": "abc123",
          "credential_id": "cred1", "resource": "endpoint",
          "effect": "read", "policy_decision": "allow"}],
    )


def test_basic_bundle(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    out = tmp_path / "bundle.zip"

    result = create_bundle(evidence, out)
    assert result["file_count"] == 3
    assert result["includes_analysis"] is False
    assert out.exists()

    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert "manifest.json" in names
        assert "messages.jsonl" in names
        assert "transcripts.jsonl" in names
        assert "control_plane.jsonl" in names

        manifest = json.loads(zf.read("manifest.json"))
        assert manifest["includes_analysis"] is False
        assert len(manifest["files"]) == 3
        for f in manifest["files"]:
            assert "sha256" in f
            assert "bytes" in f


def test_bundle_with_ground_truth(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    (evidence / "ground_truth.json").write_text("{}", encoding="utf-8")
    out = tmp_path / "bundle.zip"

    result = create_bundle(evidence, out)
    assert result["file_count"] == 4

    with zipfile.ZipFile(out) as zf:
        assert "ground_truth.json" in zf.namelist()


def test_bundle_with_analysis(tmp_path: Path) -> None:
    from orbit_ir.generator import LabConfig, generate_dataset

    evidence = tmp_path / "evidence"
    generate_dataset(evidence, LabConfig(
        agents=10, messages=50, transcripts=20, participants=5,
        spoofed_tool_calls=2, unbacked_completions=0, oracle_modifications=0,
        lateral_accesses=0, coordinators=1, seed=42,
    ))
    out = tmp_path / "bundle.zip"

    result = create_bundle(evidence, out, include_analysis=True)
    assert result["includes_analysis"] is True

    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert "analysis/findings.json" in names or "analysis/summary.json" in names


def test_bundle_missing_dir(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        create_bundle(tmp_path / "nonexistent", tmp_path / "out.zip")


def test_bundle_empty_dir(tmp_path: Path) -> None:
    import pytest

    evidence = tmp_path / "evidence"
    evidence.mkdir()

    with pytest.raises(ValueError, match="no evidence files"):
        create_bundle(evidence, tmp_path / "out.zip")


def test_bundle_manifest_hashes_consistent(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    out = tmp_path / "bundle.zip"

    create_bundle(evidence, out)

    with zipfile.ZipFile(out) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        for entry in manifest["files"]:
            assert len(entry["sha256"]) == 64
            assert entry["bytes"] > 0


def test_bundle_cli_text(tmp_path: Path) -> None:
    import io
    from contextlib import redirect_stdout
    from orbit_ir import cli

    evidence = tmp_path / "evidence"
    _make_evidence(evidence)
    out = tmp_path / "bundle.zip"

    args = cli.build_parser().parse_args(["bundle", "--input", str(evidence), "--output", str(out)])
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli._run(args)
    output = buf.getvalue()
    assert "Bundle:" in output
    assert "Files:" in output
