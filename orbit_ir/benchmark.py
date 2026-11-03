"""Performance benchmarking for orbit-ir analysis pipeline."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


def run_benchmark(input_dir: str, iterations: int = 5) -> dict[str, Any]:
    events = _load_events_for_bench(input_dir)
    event_count = len(events)

    timings: dict[str, list[float]] = {
        "load": [],
        "parse": [],
        "classify": [],
        "aggregate": [],
    }

    for _ in range(iterations):
        t0 = time.monotonic()
        raw = _bench_load(input_dir)
        timings["load"].append(time.monotonic() - t0)

        t0 = time.monotonic()
        parsed = _bench_parse(raw)
        timings["parse"].append(time.monotonic() - t0)

        t0 = time.monotonic()
        _bench_classify(parsed)
        timings["classify"].append(time.monotonic() - t0)

        t0 = time.monotonic()
        _bench_aggregate(parsed)
        timings["aggregate"].append(time.monotonic() - t0)

    results = {}
    total_avg = 0.0
    for phase, times in timings.items():
        avg = sum(times) / len(times) if times else 0
        results[phase] = {
            "avg_ms": round(avg * 1000, 2),
            "min_ms": round(min(times) * 1000, 2) if times else 0,
            "max_ms": round(max(times) * 1000, 2) if times else 0,
            "iterations": len(times),
        }
        total_avg += avg

    return {
        "event_count": event_count,
        "iterations": iterations,
        "phases": results,
        "total_avg_ms": round(total_avg * 1000, 2),
        "events_per_second": round(event_count / total_avg, 0) if total_avg > 0 else 0,
    }


def _load_events_for_bench(input_dir: str) -> list[dict]:
    events = []
    p = Path(input_dir)
    for f in sorted(p.glob("*.jsonl")):
        for line in f.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    for f in sorted(p.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            if isinstance(data, list):
                events.extend(data)
        except (json.JSONDecodeError, ValueError):
            continue
    return events


def _bench_load(input_dir: str) -> list[str]:
    lines = []
    p = Path(input_dir)
    for f in sorted(p.glob("*.jsonl")):
        lines.extend(f.read_text().splitlines())
    for f in sorted(p.glob("*.json")):
        lines.append(f.read_text())
    return lines


def _bench_parse(raw: list[str]) -> list[dict]:
    parsed = []
    for line in raw:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, list):
                parsed.extend(obj)
            elif isinstance(obj, dict):
                parsed.append(obj)
        except json.JSONDecodeError:
            continue
    return parsed


def _bench_classify(events: list[dict]) -> list[dict]:
    for ev in events:
        sev = ev.get("severity", "").lower()
        if sev in ("critical", "high"):
            ev["_class"] = "suspicious"
        else:
            ev["_class"] = "benign"
    return events


def _bench_aggregate(events: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for ev in events:
        agent = ev.get("agent_id", ev.get("agent", "unknown"))
        counts[agent] = counts.get(agent, 0) + 1
    return counts


def format_benchmark_text(result: dict[str, Any]) -> str:
    lines = [
        f"Performance Benchmark ({result['event_count']} events, {result['iterations']} iterations)\n",
        f"  Total avg: {result['total_avg_ms']:.1f}ms",
        f"  Throughput: {result['events_per_second']:.0f} events/sec\n",
        f"  {'Phase':<15s} {'Avg (ms)':>10s} {'Min (ms)':>10s} {'Max (ms)':>10s}",
        f"  {'-'*50}",
    ]
    for phase, stats in result["phases"].items():
        lines.append(
            f"  {phase:<15s} {stats['avg_ms']:>10.2f} {stats['min_ms']:>10.2f} {stats['max_ms']:>10.2f}"
        )
    lines.append("")
    return "\n".join(lines)
