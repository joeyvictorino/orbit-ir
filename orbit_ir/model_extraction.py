"""Model extraction and model stealing attempt detection in agent evidence.

Identifies attempts to extract model weights, replicate model behavior
through systematic querying, steal proprietary model outputs, and
reconstruct model internals through inference attacks.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


SYSTEMATIC_QUERY_KEYWORDS = {
    "enumerate", "systematic", "exhaustive", "brute force",
    "grid search", "sweep", "probe all", "iterate over",
    "all combinations", "permutation", "every input",
    "batch query", "mass query", "automated query",
}

WEIGHT_EXTRACTION_KEYWORDS = {
    "model weights", "parameters", "gradient", "backprop",
    "weight matrix", "embedding layer", "attention head",
    "layer output", "hidden state", "activation",
    "checkpoint", "safetensors", "model file", "export model",
    "download model", "save weights", "dump model",
}

BEHAVIOR_CLONE_KEYWORDS = {
    "distillation", "knowledge distillation", "student model",
    "teacher model", "mimic", "clone model", "replicate",
    "copy behavior", "shadow model", "surrogate model",
    "functional clone", "black-box clone", "model stealing",
}

OUTPUT_HARVEST_KEYWORDS = {
    "collect outputs", "harvest responses", "log predictions",
    "record answers", "capture logits", "probability distribution",
    "confidence score", "token probability", "output distribution",
    "prediction log", "response dataset", "training data generation",
}

INFERENCE_ATTACK_KEYWORDS = {
    "membership inference", "model inversion", "attribute inference",
    "data reconstruction", "training data extraction", "memorization",
    "canary", "extraction attack", "model oracle",
    "decision boundary", "feature importance", "saliency map",
}

EXTRACTION_TYPES = {
    "systematic-query": "Systematic querying to map model behavior",
    "weight-extraction": "Attempt to extract or access model weights/parameters",
    "behavior-cloning": "Model behavior cloning through distillation or mimicry",
    "output-harvesting": "Harvesting model outputs for training a clone",
    "inference-attack": "Inference attack to reconstruct model internals or training data",
}

_KEYWORD_SETS = {
    "systematic-query": SYSTEMATIC_QUERY_KEYWORDS,
    "weight-extraction": WEIGHT_EXTRACTION_KEYWORDS,
    "behavior-cloning": BEHAVIOR_CLONE_KEYWORDS,
    "output-harvesting": OUTPUT_HARVEST_KEYWORDS,
    "inference-attack": INFERENCE_ATTACK_KEYWORDS,
}


@dataclass
class Pattern:
    extraction_type: str
    agent: str
    timestamp: str
    description: str
    evidence_field: str
    matched_keywords: list[str]
    severity: str = "high"


@dataclass
class ExtractionChain:
    agent: str
    types_involved: list[str]
    pattern_count: int
    first_seen: str
    last_seen: str
    severity: str = "critical"


@dataclass
class Summary:
    total_events: int = 0
    total_patterns: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    agents_involved: list[str] = field(default_factory=list)
    extraction_chains: int = 0


@dataclass
class Report:
    patterns: list[Pattern] = field(default_factory=list)
    chains: list[ExtractionChain] = field(default_factory=list)
    summary: Summary = field(default_factory=Summary)


def _match_keywords(text: str, keyword_set: set[str]) -> list[str]:
    lower = text.lower()
    return sorted(kw for kw in keyword_set if kw in lower)


def _detect_high_volume_queries(events: list[dict[str, Any]]) -> list[Pattern]:
    """Detect abnormally high query volumes from a single agent."""
    patterns: list[Pattern] = []
    agent_query_counts: dict[str, list[dict]] = defaultdict(list)

    for ev in events:
        agent = ev.get("agent", ev.get("agent_id", "unknown"))
        if ev.get("type") in ("tool_call", "function_call", "api_call", "query"):
            agent_query_counts[agent].append(ev)

    for agent, queries in agent_query_counts.items():
        if len(queries) >= 50:
            patterns.append(Pattern(
                extraction_type="systematic-query",
                agent=agent,
                timestamp=queries[0].get("timestamp", ""),
                description=f"Agent issued {len(queries)} queries — potential systematic extraction",
                evidence_field="type",
                matched_keywords=["high volume"],
                severity="critical" if len(queries) >= 100 else "high",
            ))

    return patterns


def _detect_keyword_patterns(events: list[dict[str, Any]]) -> list[Pattern]:
    """Detect extraction patterns via keyword matching."""
    patterns: list[Pattern] = []

    for ev in events:
        agent = ev.get("agent", ev.get("agent_id", "unknown"))
        ts = ev.get("timestamp", "")

        for field_name in ("content", "tool", "args", "result", "message"):
            text = str(ev.get(field_name, ""))
            if not text:
                continue

            for etype, kw_set in _KEYWORD_SETS.items():
                matched = _match_keywords(text, kw_set)
                if len(matched) >= 2:
                    severity = _classify_severity(etype, len(matched))
                    patterns.append(Pattern(
                        extraction_type=etype,
                        agent=agent,
                        timestamp=ts,
                        description=f"{EXTRACTION_TYPES[etype]} ({len(matched)} indicators in {field_name})",
                        evidence_field=field_name,
                        matched_keywords=matched,
                        severity=severity,
                    ))

    return patterns


def _classify_severity(extraction_type: str, match_count: int) -> str:
    if extraction_type in ("weight-extraction", "inference-attack"):
        return "critical" if match_count >= 3 else "high"
    if extraction_type == "behavior-cloning":
        return "critical" if match_count >= 3 else "high"
    if extraction_type == "output-harvesting":
        return "high" if match_count >= 2 else "medium"
    return "high" if match_count >= 3 else "medium"


def _build_chains(patterns: list[Pattern]) -> list[ExtractionChain]:
    """Group patterns by agent to find multi-technique extraction campaigns."""
    agent_patterns: dict[str, list[Pattern]] = defaultdict(list)
    for p in patterns:
        agent_patterns[p.agent].append(p)

    chains: list[ExtractionChain] = []
    for agent, pats in agent_patterns.items():
        types = sorted(set(p.extraction_type for p in pats))
        if len(types) >= 2:
            timestamps = [p.timestamp for p in pats if p.timestamp]
            chains.append(ExtractionChain(
                agent=agent,
                types_involved=types,
                pattern_count=len(pats),
                first_seen=min(timestamps) if timestamps else "",
                last_seen=max(timestamps) if timestamps else "",
                severity="critical",
            ))

    return sorted(chains, key=lambda c: c.pattern_count, reverse=True)


def _load_events(evidence_dir: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    ed = Path(evidence_dir)
    for name in ("transcripts.jsonl", "control_plane.jsonl"):
        fp = ed / name
        if fp.exists():
            for line in fp.read_text().splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return events


def analyze(events: list[dict[str, Any]]) -> Report:
    kw_patterns = _detect_keyword_patterns(events)
    volume_patterns = _detect_high_volume_queries(events)
    all_patterns = kw_patterns + volume_patterns

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_patterns.sort(key=lambda p: (severity_order.get(p.severity, 9), p.timestamp))

    chains = _build_chains(all_patterns)

    by_type: dict[str, int] = defaultdict(int)
    agents = set()
    for p in all_patterns:
        by_type[p.extraction_type] += 1
        agents.add(p.agent)

    summary = Summary(
        total_events=len(events),
        total_patterns=len(all_patterns),
        by_type=dict(by_type),
        agents_involved=sorted(agents),
        extraction_chains=len(chains),
    )

    return Report(patterns=all_patterns, chains=chains, summary=summary)


def format_text(report: Report) -> str:
    lines = [
        "Model Extraction Detection Report",
        "=" * 50,
        "",
        f"  Total events analyzed:   {report.summary.total_events}",
        f"  Extraction patterns:     {report.summary.total_patterns}",
        f"  Extraction chains:       {report.summary.extraction_chains}",
        f"  Agents involved:         {len(report.summary.agents_involved)}",
        "",
    ]

    if report.summary.by_type:
        lines.append("  Patterns by type:")
        for t, c in sorted(report.summary.by_type.items()):
            lines.append(f"    {t}: {c}")
        lines.append("")

    for p in report.patterns:
        lines.append(f"  [{p.severity.upper()}] {p.extraction_type}")
        lines.append(f"    Agent: {p.agent}")
        if p.timestamp:
            lines.append(f"    Time:  {p.timestamp}")
        lines.append(f"    Detail: {p.description}")
        lines.append(f"    Keywords: {', '.join(p.matched_keywords)}")
        lines.append("")

    if report.chains:
        lines.append("  Extraction Chains:")
        for c in report.chains:
            lines.append(f"    Agent: {c.agent} ({c.pattern_count} patterns)")
            lines.append(f"    Types: {', '.join(c.types_involved)}")
            if c.first_seen:
                lines.append(f"    Window: {c.first_seen} -> {c.last_seen}")
            lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: Report) -> str:
    return json.dumps(asdict(report), indent=2) + "\n"
