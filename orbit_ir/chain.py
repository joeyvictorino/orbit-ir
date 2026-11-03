"""Pipeline composition — chain multiple orbit-ir steps into a single run.

Reads a YAML pipeline definition and executes steps sequentially,
piping the output directory of one step as input to the next.
"""
from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml


SUPPORTED_COMMANDS = {
    "normalize",
    "enrich",
    "tag",
    "analyze",
    "report",
    "export",
    "deduplicate",
    "correlate",
    "stats",
    "replay",
}


@dataclass
class ChainStep:
    command: str
    args: dict = field(default_factory=dict)


def parse_chain(content: str) -> list[ChainStep]:
    data = yaml.safe_load(content)
    if not isinstance(data, dict) or "steps" not in data:
        raise ValueError("pipeline YAML must have a top-level 'steps' list")

    steps_raw = data["steps"]
    if not isinstance(steps_raw, list) or len(steps_raw) == 0:
        raise ValueError("pipeline 'steps' must be a non-empty list")

    steps: list[ChainStep] = []
    for i, raw in enumerate(steps_raw):
        if not isinstance(raw, dict) or "command" not in raw:
            raise ValueError(f"step {i}: must be a mapping with a 'command' key")
        cmd = raw["command"]
        if cmd not in SUPPORTED_COMMANDS:
            raise ValueError(
                f"step {i}: unknown command {cmd!r}; supported: {', '.join(sorted(SUPPORTED_COMMANDS))}"
            )
        args = raw.get("args", {})
        if not isinstance(args, dict):
            args = {}
        steps.append(ChainStep(command=cmd, args=args))

    return steps


def run_chain(
    steps: list[ChainStep],
    base_dir: Path,
    work_dir: Path,
) -> dict:
    base_dir = Path(base_dir)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    current_input = base_dir
    step_results: list[dict] = []
    total_start = time.monotonic()

    for i, step in enumerate(steps):
        step_start = time.monotonic()
        step_output = work_dir / f"step_{i}_{step.command}"
        step_output.mkdir(parents=True, exist_ok=True)

        try:
            result = _run_step(step, current_input, step_output)
            elapsed = time.monotonic() - step_start
            step_results.append({
                "step": i,
                "command": step.command,
                "status": "ok",
                "duration_seconds": round(elapsed, 3),
                "details": result,
            })
            if step_output.is_dir() and any(step_output.iterdir()):
                current_input = step_output
        except Exception as exc:
            elapsed = time.monotonic() - step_start
            step_results.append({
                "step": i,
                "command": step.command,
                "status": "error",
                "duration_seconds": round(elapsed, 3),
                "error": str(exc),
            })
            break

    total_elapsed = time.monotonic() - total_start
    succeeded = sum(1 for s in step_results if s["status"] == "ok")

    return {
        "steps": step_results,
        "total_steps": len(steps),
        "succeeded": succeeded,
        "failed": len(step_results) - succeeded,
        "total_duration_seconds": round(total_elapsed, 3),
        "final_output": str(current_input),
    }


def _run_step(step: ChainStep, input_dir: Path, output_dir: Path) -> dict:
    cmd = step.command
    args = step.args

    if cmd == "normalize":
        from .normalize import normalize_evidence
        renames = args.get("renames")
        return normalize_evidence(input_dir, output_dir, renames=renames)

    elif cmd == "enrich":
        from .enrich import enrich_evidence
        enrichments_str = args.get("enrichments")
        enrichments = enrichments_str.split(",") if enrichments_str else None
        return enrich_evidence(input_dir, output_dir, enrichments=enrichments)

    elif cmd == "tag":
        from .tag import tag_events
        rules = args.get("rules", [])
        return tag_events(input_dir, output_dir, rules)

    elif cmd == "analyze":
        from .analyzer import analyze_dataset
        return analyze_dataset(input_dir, output_dir)

    elif cmd == "report":
        from .report_gen import generate_report, ReportConfig
        sections_str = args.get("sections")
        sections = sections_str.split(",") if sections_str else None
        config = ReportConfig(
            title=args.get("title", "Orbit-IR Analysis Report"),
            sections=sections or list(("summary", "findings", "agents", "timeline", "tools", "recommendations")),
            severity_threshold=args.get("severity"),
            format=args.get("format", "text"),
        )
        text = generate_report(input_dir, config)
        report_path = output_dir / "report.txt"
        if config.format == "markdown":
            report_path = output_dir / "report.md"
        report_path.write_text(text, encoding="utf-8")
        return {"output_file": str(report_path), "length": len(text)}

    elif cmd == "export":
        from .export import export_findings
        fmt = args.get("format", "csv")
        findings_path = input_dir / "findings.json"
        if not findings_path.exists():
            return {"skipped": True, "reason": "no findings.json in input"}
        out_path = output_dir / f"findings.{fmt}"
        text = export_findings(findings_path, fmt, output_path=out_path)
        return {"output_file": str(out_path), "format": fmt}

    elif cmd == "deduplicate":
        from .dedup import deduplicate_findings
        findings_path = input_dir / "findings.json"
        if not findings_path.exists():
            return {"skipped": True, "reason": "no findings.json"}
        all_findings = json.loads(findings_path.read_text(encoding="utf-8"))
        strategy = args.get("strategy", "exact")
        unique, removed = deduplicate_findings(all_findings, strategy=strategy)
        out_path = output_dir / "findings.json"
        out_path.write_text(json.dumps(unique, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {"unique": len(unique), "removed": len(removed), "strategy": strategy}

    elif cmd == "correlate":
        from .correlate import correlate_events
        window = args.get("time_window", 5)
        result = correlate_events(input_dir, time_window_seconds=window)
        out_path = output_dir / "correlations.json"
        out_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {"correlations": result.get("total_correlations", 0)}

    elif cmd == "stats":
        from .stats import evidence_stats
        s = evidence_stats(input_dir)
        out_path = output_dir / "stats.json"
        out_path.write_text(json.dumps(s, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return s

    elif cmd == "replay":
        from .replay import replay_events as _replay
        events = _replay(input_dir, annotate=True)
        out_path = output_dir / "replay.json"
        out_path.write_text(json.dumps(events, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        return {"events": len(events)}

    return {"skipped": True, "reason": f"unhandled command: {cmd}"}


def format_chain_text(result: dict) -> str:
    lines: list[str] = []
    lines.append(f"Pipeline: {result['succeeded']}/{result['total_steps']} steps succeeded "
                 f"({result['total_duration_seconds']:.1f}s)")
    lines.append("")
    for s in result["steps"]:
        status = "OK" if s["status"] == "ok" else "FAIL"
        lines.append(f"  [{status}] step {s['step']}: {s['command']} ({s['duration_seconds']:.3f}s)")
        if s["status"] == "error":
            lines.append(f"         error: {s['error']}")
    lines.append("")
    lines.append(f"Final output: {result['final_output']}")
    return "\n".join(lines) + "\n"
