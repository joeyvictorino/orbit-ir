"""Tests for performance benchmarking."""

import json
import tempfile
from pathlib import Path

from orbit_ir.benchmark import run_benchmark, format_benchmark_text, _bench_parse, _bench_classify, _bench_aggregate


def _write_events(d: Path, events: list[dict], name: str = "events.jsonl") -> None:
    lines = [json.dumps(e) for e in events]
    (d / name).write_text("\n".join(lines))


def test_benchmark_empty_dir():
    with tempfile.TemporaryDirectory() as d:
        result = run_benchmark(d, iterations=2)
        assert result["event_count"] == 0
        assert result["iterations"] == 2
        assert "load" in result["phases"]


def test_benchmark_basic():
    with tempfile.TemporaryDirectory() as d:
        events = [
            {"agent_id": "a1", "severity": "high", "tool_name": "bash"},
            {"agent_id": "a2", "severity": "low", "tool_name": "read"},
        ]
        _write_events(Path(d), events)
        result = run_benchmark(d, iterations=3)
        assert result["event_count"] == 2
        assert result["iterations"] == 3
        assert result["total_avg_ms"] >= 0
        for phase in ("load", "parse", "classify", "aggregate"):
            assert phase in result["phases"]
            assert result["phases"][phase]["iterations"] == 3


def test_benchmark_text_format():
    with tempfile.TemporaryDirectory() as d:
        events = [{"agent_id": "a1"}]
        _write_events(Path(d), events)
        result = run_benchmark(d, iterations=2)
        text = format_benchmark_text(result)
        assert "Performance Benchmark" in text
        assert "load" in text
        assert "events/sec" in text


def test_bench_parse():
    raw = ['{"a": 1}', '{"b": 2}', '', 'bad-json', '[{"c": 3}]']
    parsed = _bench_parse(raw)
    assert len(parsed) == 3


def test_bench_classify():
    events = [
        {"severity": "critical"},
        {"severity": "low"},
        {"severity": "high"},
        {},
    ]
    classified = _bench_classify(events)
    assert classified[0]["_class"] == "suspicious"
    assert classified[1]["_class"] == "benign"
    assert classified[2]["_class"] == "suspicious"
    assert classified[3]["_class"] == "benign"


def test_bench_aggregate():
    events = [
        {"agent_id": "a1"},
        {"agent_id": "a1"},
        {"agent_id": "a2"},
        {"agent": "a3"},
    ]
    counts = _bench_aggregate(events)
    assert counts["a1"] == 2
    assert counts["a2"] == 1
    assert counts["a3"] == 1


def test_benchmark_throughput():
    with tempfile.TemporaryDirectory() as d:
        events = [{"agent_id": f"a{i}", "severity": "low"} for i in range(50)]
        _write_events(Path(d), events)
        result = run_benchmark(d, iterations=2)
        assert result["events_per_second"] > 0
