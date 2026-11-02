"""Enrich evidence files with metadata: tool docs, inferred roles, risk tags."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

TOOL_DOCS: dict[str, str] = {
    "http_get": "HTTP GET request — reads data from an external URL",
    "http_post": "HTTP POST request — sends data to an external URL",
    "file_read": "Reads contents of a local file",
    "file_write": "Writes contents to a local file",
    "shell_exec": "Executes a shell command on the host",
    "db_query": "Runs a database query (SQL or NoSQL)",
    "send_message": "Sends a message to another agent or channel",
    "code_exec": "Executes code in a sandbox or runtime",
    "api_call": "Makes a generic API call to an external service",
    "read_memory": "Reads from a shared memory or context store",
    "write_memory": "Writes to a shared memory or context store",
}

RISK_TAGS: dict[str, list[str]] = {
    "shell_exec": ["code_execution", "host_access"],
    "code_exec": ["code_execution"],
    "db_query": ["data_access", "persistence"],
    "file_write": ["file_system_write", "persistence"],
    "file_read": ["file_system_read", "data_access"],
    "http_post": ["network_egress", "data_exfiltration_risk"],
    "http_get": ["network_egress"],
    "api_call": ["network_egress", "external_service"],
    "write_memory": ["persistence", "shared_state"],
    "send_message": ["inter_agent_communication"],
}

ALL_ENRICHMENTS = ("tool_docs", "agent_roles", "risk_tags")


def _load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def _infer_roles(
    messages: list[dict],
    transcripts: list[dict],
    control_plane: list[dict],
) -> dict[str, str]:
    """Infer agent roles based on message and tool patterns.

    - orchestrator: sends messages to many distinct agents
    - monitor: mostly reads (http_get, file_read, read_memory, db_query) with few writes
    - worker: default for agents that don't fit the above
    """
    sent_counts: dict[str, set[str]] = defaultdict(set)
    received_counts: Counter[str] = Counter()

    for m in messages:
        agent = m.get("agent_id", "")
        recipient = m.get("recipient_agent_id")
        if agent:
            if recipient:
                sent_counts[agent].add(recipient)
            received_counts[agent] += 1
        if recipient:
            received_counts[recipient] += 1

    tool_usage: dict[str, Counter[str]] = defaultdict(Counter)
    for t in transcripts:
        agent = t.get("agent_id", "")
        tool = t.get("claimed_tool", t.get("actual_tool", ""))
        if agent and tool:
            tool_usage[agent][tool] += 1

    for cp in control_plane:
        agent = cp.get("agent_id", "")
        tool = cp.get("tool", "")
        if agent and tool:
            tool_usage[agent][tool] += 1

    all_agents: set[str] = set()
    all_agents.update(sent_counts.keys())
    all_agents.update(received_counts.keys())
    all_agents.update(tool_usage.keys())

    read_tools = {"http_get", "file_read", "read_memory", "db_query"}

    roles: dict[str, str] = {}
    for agent in all_agents:
        distinct_recipients = len(sent_counts.get(agent, set()))
        tools = tool_usage.get(agent, Counter())
        total_tool_calls = sum(tools.values())
        read_calls = sum(tools.get(t, 0) for t in read_tools)

        if distinct_recipients >= 3:
            roles[agent] = "orchestrator"
        elif total_tool_calls > 0 and read_calls / total_tool_calls > 0.7:
            roles[agent] = "monitor"
        else:
            roles[agent] = "worker"

    return roles


def enrich_evidence(
    evidence_dir: Path,
    output_dir: Path,
    enrichments: list[str] | None = None,
) -> dict:
    """Enrich evidence files and write to output_dir.

    Returns a summary of enrichments applied.
    """
    evidence_dir = Path(evidence_dir)
    output_dir = Path(output_dir)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"not a directory: {evidence_dir}")

    active = list(enrichments) if enrichments else list(ALL_ENRICHMENTS)
    for e in active:
        if e not in ALL_ENRICHMENTS:
            raise ValueError(f"unknown enrichment: {e!r} (valid: {', '.join(ALL_ENRICHMENTS)})")

    messages = _load_jsonl(evidence_dir / "messages.jsonl")
    transcripts = _load_jsonl(evidence_dir / "transcripts.jsonl")
    control_plane = _load_jsonl(evidence_dir / "control_plane.jsonl")

    summary: dict[str, int] = {}

    # Infer roles once (needed by agent_roles enrichment).
    roles: dict[str, str] = {}
    if "agent_roles" in active:
        roles = _infer_roles(messages, transcripts, control_plane)

    if "tool_docs" in active:
        count = 0
        for t in transcripts:
            tool = t.get("claimed_tool", t.get("actual_tool", ""))
            if tool in TOOL_DOCS:
                t["tool_description"] = TOOL_DOCS[tool]
                count += 1
        for cp in control_plane:
            tool = cp.get("tool", "")
            if tool in TOOL_DOCS:
                cp["tool_description"] = TOOL_DOCS[tool]
                count += 1
        summary["tool_docs_applied"] = count

    if "agent_roles" in active:
        count = 0
        for collection in (messages, transcripts, control_plane):
            for row in collection:
                agent = row.get("agent_id", "")
                if agent in roles:
                    row["inferred_role"] = roles[agent]
                    count += 1
        summary["agent_roles_applied"] = count

    if "risk_tags" in active:
        count = 0
        for t in transcripts:
            tool = t.get("claimed_tool", t.get("actual_tool", ""))
            if tool in RISK_TAGS:
                t["risk_tags"] = RISK_TAGS[tool]
                count += 1
        for cp in control_plane:
            tool = cp.get("tool", "")
            if tool in RISK_TAGS:
                cp["risk_tags"] = RISK_TAGS[tool]
                count += 1
        summary["risk_tags_applied"] = count

    output_dir.mkdir(parents=True, exist_ok=True)
    if messages:
        _write_jsonl(output_dir / "messages.jsonl", messages)
    if transcripts:
        _write_jsonl(output_dir / "transcripts.jsonl", transcripts)
    if control_plane:
        _write_jsonl(output_dir / "control_plane.jsonl", control_plane)

    # Copy ground_truth.json if present.
    gt = evidence_dir / "ground_truth.json"
    if gt.exists():
        (output_dir / "ground_truth.json").write_text(
            gt.read_text(encoding="utf-8"), encoding="utf-8"
        )

    return {
        "enrichments": active,
        "files_written": len([f for f in output_dir.iterdir() if f.is_file()]),
        "summary": summary,
    }


def format_enrich_text(result: dict) -> str:
    """Human-readable enrichment summary."""
    lines = [
        f"Enrichments applied: {', '.join(result['enrichments'])}",
        f"Files written: {result['files_written']}",
    ]
    for k, v in result.get("summary", {}).items():
        lines.append(f"  {k}: {v}")
    return "\n".join(lines) + "\n"
