"""Run multiple orbit-ir commands in sequence with shared context."""

from __future__ import annotations

import json
import shlex
import sys
import time
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any


@dataclass
class StepResult:
    name: str
    command: str
    exit_code: int
    duration_ms: int
    output: str = ""
    error: str = ""


@dataclass
class BatchResult:
    steps: list[StepResult] = field(default_factory=list)
    total_ms: int = 0
    passed: int = 0
    failed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_ms": self.total_ms,
            "passed": self.passed,
            "failed": self.failed,
            "steps": [
                {
                    "name": s.name,
                    "command": s.command,
                    "exit_code": s.exit_code,
                    "duration_ms": s.duration_ms,
                }
                for s in self.steps
            ],
        }


def parse_batch_file(path: Path) -> list[dict[str, str]]:
    text = path.read_text()
    steps: list[dict[str, str]] = []

    if path.suffix in (".yaml", ".yml"):
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("- "):
                cmd = line[2:].strip()
                if cmd.startswith("name:"):
                    pass
                elif cmd:
                    steps.append({"name": cmd.split()[0], "command": cmd})
        if not steps:
            import yaml  # noqa: F811
            data = yaml.safe_load(text)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        steps.append({
                            "name": item.get("name", item.get("command", "").split()[0]),
                            "command": item.get("command", ""),
                        })
                    elif isinstance(item, str):
                        steps.append({"name": item.split()[0], "command": item})
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            steps.append({"name": line.split()[0], "command": line})

    return steps


def run_batch(steps: list[dict[str, str]], variables: dict[str, str] | None = None) -> BatchResult:
    from . import cli as cli_module

    result = BatchResult()
    start_all = time.monotonic()
    env = dict(variables or {})

    for step in steps:
        cmd_str = step["command"]
        for k, v in env.items():
            cmd_str = cmd_str.replace(f"${{{k}}}", v)
            cmd_str = cmd_str.replace(f"${k}", v)

        parts = shlex.split(cmd_str)
        if parts and parts[0] in ("orbit-ir", "orbit_ir"):
            parts = parts[1:]

        name = step.get("name", parts[0] if parts else "unknown")
        old_stdout, old_stderr = sys.stdout, sys.stderr
        capture_out = StringIO()
        capture_err = StringIO()
        sys.stdout = capture_out
        sys.stderr = capture_err

        t0 = time.monotonic()
        exit_code = 0
        try:
            args = cli_module.build_parser().parse_args(parts)
            cli_module._run(args)
        except SystemExit as e:
            exit_code = e.code if isinstance(e.code, int) else 1
        except Exception as e:
            capture_err.write(f"error: {e}\n")
            exit_code = 2
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
        elapsed = int((time.monotonic() - t0) * 1000)

        sr = StepResult(
            name=name,
            command=step["command"],
            exit_code=exit_code,
            duration_ms=elapsed,
            output=capture_out.getvalue(),
            error=capture_err.getvalue(),
        )
        result.steps.append(sr)
        if exit_code == 0:
            result.passed += 1
        else:
            result.failed += 1
            break

    result.total_ms = int((time.monotonic() - start_all) * 1000)
    return result


def format_batch_text(result: BatchResult) -> str:
    lines: list[str] = []
    lines.append(f"Batch: {result.passed} passed, {result.failed} failed, {result.total_ms}ms total\n")
    for s in result.steps:
        mark = "PASS" if s.exit_code == 0 else "FAIL"
        lines.append(f"  [{mark}] {s.name} ({s.duration_ms}ms)")
        if s.exit_code != 0 and s.error:
            for eline in s.error.strip().splitlines()[:3]:
                lines.append(f"         {eline}")
    lines.append("")
    return "\n".join(lines)
