"""Tests for orbit_ir.batch module."""
import json
from pathlib import Path

from orbit_ir.batch import parse_batch_file, run_batch, format_batch_text, BatchResult, StepResult


def test_parse_batch_file_text(tmp_path):
    f = tmp_path / "batch.txt"
    f.write_text("schema\nversion\n")
    steps = parse_batch_file(f)
    assert len(steps) == 2
    assert steps[0]["command"] == "schema"
    assert steps[1]["command"] == "version"


def test_parse_batch_file_comments(tmp_path):
    f = tmp_path / "batch.txt"
    f.write_text("# comment\nschema\n\n# another\nversion\n")
    steps = parse_batch_file(f)
    assert len(steps) == 2


def test_run_batch_schema(tmp_path):
    steps = [{"name": "schema", "command": "schema"}]
    result = run_batch(steps)
    assert result.passed == 1
    assert result.failed == 0
    assert result.steps[0].exit_code == 0


def test_run_batch_stops_on_failure():
    steps = [
        {"name": "bad", "command": "stats --input /nonexistent/path"},
        {"name": "schema", "command": "schema"},
    ]
    result = run_batch(steps)
    assert result.failed == 1
    assert len(result.steps) == 1


def test_format_batch_text():
    result = BatchResult(
        steps=[
            StepResult(name="schema", command="schema", exit_code=0, duration_ms=5),
            StepResult(name="version", command="version", exit_code=0, duration_ms=3),
        ],
        total_ms=8,
        passed=2,
        failed=0,
    )
    text = format_batch_text(result)
    assert "2 passed" in text
    assert "0 failed" in text
    assert "PASS" in text


def test_format_batch_failure():
    result = BatchResult(
        steps=[
            StepResult(name="bad", command="bad-cmd", exit_code=2, duration_ms=1, error="not found"),
        ],
        total_ms=1,
        passed=0,
        failed=1,
    )
    text = format_batch_text(result)
    assert "FAIL" in text
    assert "1 failed" in text


def test_run_batch_variable_substitution(tmp_path):
    ev_dir = tmp_path / "evidence"
    ev_dir.mkdir()
    (ev_dir / "messages.jsonl").write_text(
        json.dumps({"agent_id": "a1", "timestamp": "2025-01-01T00:00:00Z"}) + "\n"
    )
    steps = [{"name": "stats", "command": "stats --input ${INPUT} --format json"}]
    result = run_batch(steps, variables={"INPUT": str(ev_dir)})
    assert result.passed == 1
