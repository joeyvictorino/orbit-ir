"""Model poisoning and backdoor detection in agent evidence.

Identifies attempts to poison training data, inject backdoors into models,
corrupt fine-tuning pipelines, manipulate embeddings, and plant trigger
patterns for adversarial model behavior.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


DATA_POISONING_KEYWORDS = {
    "poison training", "corrupt data", "inject sample", "adversarial sample",
    "mislabel", "label flip", "backdoor sample", "trojan data",
    "data manipulation", "training corruption", "poison dataset",
}

BACKDOOR_INJECT_KEYWORDS = {
    "inject backdoor", "plant trigger", "trojan model", "hidden behavior",
    "backdoor pattern", "trigger pattern", "sleeper agent", "dormant behavior",
    "activation trigger", "backdoor activation", "covert behavior",
}

FINETUNE_CORRUPT_KEYWORDS = {
    "corrupt finetune", "malicious finetune", "hijack training",
    "training hijack", "gradient manipulation", "loss manipulation",
    "optimizer poisoning", "checkpoint tampering", "weight modification",
    "finetune injection", "training pipeline attack",
}

EMBEDDING_MANIP_KEYWORDS = {
    "embedding manipulation", "vector poisoning", "corrupt embedding",
    "adversarial embedding", "manipulate vector", "embedding injection",
    "semantic manipulation", "representation attack", "latent space attack",
    "embedding backdoor",
}

TRIGGER_PLANT_KEYWORDS = {
    "plant trigger", "trigger phrase", "activation phrase", "magic word",
    "secret command", "hidden command", "backdoor trigger", "code word",
    "trigger sequence", "activation sequence", "planted phrase",
}

MODEL_POISONING_TYPES = {
    "data-poisoning",
    "backdoor-injection",
    "finetune-corruption",
    "embedding-manipulation",
    "trigger-planting",
}


@dataclass
class ModelPoisoningPattern:
    pattern_type: str
    agent_id: str
    description: str
    evidence_file: str
    line_number: int = 0
    severity: str = "medium"
    matched_keywords: list[str] = field(default_factory=list)


@dataclass
class ModelPoisoningSummary:
    agent_id: str
    total_patterns: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    severity_counts: dict[str, int] = field(default_factory=dict)
    has_chain: bool = False


@dataclass
class ModelPoisoningReport:
    patterns: list[ModelPoisoningPattern] = field(default_factory=list)
    agent_summaries: list[ModelPoisoningSummary] = field(default_factory=list)
    chains: list[dict[str, Any]] = field(default_factory=list)
    total_patterns: int = 0
    total_agents: int = 0


def analyze_model_poisoning(evidence_dir: Path) -> ModelPoisoningReport:
    events = _load_events(evidence_dir)
    patterns: list[ModelPoisoningPattern] = []

    for ev_file, ev_list in events.items():
        for i, ev in enumerate(ev_list):
            agent = ev.get("agent_id", ev.get("agent", "unknown"))
            text = json.dumps(ev).lower()

            patterns.extend(_detect_data_poisoning(agent, text, ev_file, i))
            patterns.extend(_detect_backdoor_injection(agent, text, ev_file, i))
            patterns.extend(_detect_finetune_corruption(agent, text, ev_file, i))
            patterns.extend(_detect_embedding_manipulation(agent, text, ev_file, i))
            patterns.extend(_detect_trigger_planting(agent, text, ev_file, i))

    for p in patterns:
        p.severity = _classify_severity(p)

    chains = _detect_poisoning_chains(patterns)

    agent_map: dict[str, list[ModelPoisoningPattern]] = defaultdict(list)
    for p in patterns:
        agent_map[p.agent_id].append(p)

    summaries = []
    for agent_id, agent_patterns in sorted(agent_map.items()):
        by_type: dict[str, int] = defaultdict(int)
        sev: dict[str, int] = defaultdict(int)
        for p in agent_patterns:
            by_type[p.pattern_type] += 1
            sev[p.severity] += 1
        summaries.append(ModelPoisoningSummary(
            agent_id=agent_id,
            total_patterns=len(agent_patterns),
            by_type=dict(by_type),
            severity_counts=dict(sev),
            has_chain=any(agent_id in c.get("agents", []) for c in chains),
        ))

    return ModelPoisoningReport(
        patterns=patterns,
        agent_summaries=summaries,
        chains=chains,
        total_patterns=len(patterns),
        total_agents=len(agent_map),
    )


def _detect_data_poisoning(agent: str, text: str, ev_file: str, line: int) -> list[ModelPoisoningPattern]:
    matched = [kw for kw in DATA_POISONING_KEYWORDS if kw in text]
    if not matched:
        return []
    return [ModelPoisoningPattern(
        pattern_type="data-poisoning",
        agent_id=agent,
        description=f"Data poisoning indicators: {', '.join(matched[:3])}",
        evidence_file=ev_file,
        line_number=line,
        matched_keywords=matched,
    )]


def _detect_backdoor_injection(agent: str, text: str, ev_file: str, line: int) -> list[ModelPoisoningPattern]:
    matched = [kw for kw in BACKDOOR_INJECT_KEYWORDS if kw in text]
    if not matched:
        return []
    return [ModelPoisoningPattern(
        pattern_type="backdoor-injection",
        agent_id=agent,
        description=f"Backdoor injection indicators: {', '.join(matched[:3])}",
        evidence_file=ev_file,
        line_number=line,
        matched_keywords=matched,
    )]


def _detect_finetune_corruption(agent: str, text: str, ev_file: str, line: int) -> list[ModelPoisoningPattern]:
    matched = [kw for kw in FINETUNE_CORRUPT_KEYWORDS if kw in text]
    if not matched:
        return []
    return [ModelPoisoningPattern(
        pattern_type="finetune-corruption",
        agent_id=agent,
        description=f"Fine-tune corruption indicators: {', '.join(matched[:3])}",
        evidence_file=ev_file,
        line_number=line,
        matched_keywords=matched,
    )]


def _detect_embedding_manipulation(agent: str, text: str, ev_file: str, line: int) -> list[ModelPoisoningPattern]:
    matched = [kw for kw in EMBEDDING_MANIP_KEYWORDS if kw in text]
    if not matched:
        return []
    return [ModelPoisoningPattern(
        pattern_type="embedding-manipulation",
        agent_id=agent,
        description=f"Embedding manipulation indicators: {', '.join(matched[:3])}",
        evidence_file=ev_file,
        line_number=line,
        matched_keywords=matched,
    )]


def _detect_trigger_planting(agent: str, text: str, ev_file: str, line: int) -> list[ModelPoisoningPattern]:
    matched = [kw for kw in TRIGGER_PLANT_KEYWORDS if kw in text]
    if not matched:
        return []
    return [ModelPoisoningPattern(
        pattern_type="trigger-planting",
        agent_id=agent,
        description=f"Trigger planting indicators: {', '.join(matched[:3])}",
        evidence_file=ev_file,
        line_number=line,
        matched_keywords=matched,
    )]


def _classify_severity(p: ModelPoisoningPattern) -> str:
    high_types = {"backdoor-injection", "trigger-planting"}
    if p.pattern_type in high_types:
        return "high"
    if len(p.matched_keywords) >= 3:
        return "high"
    if p.pattern_type == "finetune-corruption":
        return "high"
    if len(p.matched_keywords) >= 2:
        return "medium"
    return "low"


def _detect_poisoning_chains(patterns: list[ModelPoisoningPattern]) -> list[dict[str, Any]]:
    agent_types: dict[str, set[str]] = defaultdict(set)
    for p in patterns:
        agent_types[p.agent_id].add(p.pattern_type)

    chains = []
    for agent_id, types in agent_types.items():
        supply = types & {"data-poisoning", "finetune-corruption", "embedding-manipulation"}
        deploy = types & {"backdoor-injection", "trigger-planting"}
        if supply and deploy:
            chains.append(_build_poisoning_chain(agent_id, supply, deploy, patterns))

    return chains


def _build_poisoning_chain(agent_id: str, supply: set[str], deploy: set[str],
                           patterns: list[ModelPoisoningPattern]) -> dict[str, Any]:
    for p in patterns:
        if p.agent_id == agent_id:
            p.severity = "critical"

    return {
        "agents": [agent_id],
        "supply_types": sorted(supply),
        "deploy_types": sorted(deploy),
        "risk": "critical",
        "description": f"Agent {agent_id} shows both supply-chain poisoning ({', '.join(sorted(supply))}) "
                       f"and deployment ({', '.join(sorted(deploy))}) patterns",
    }


def format_text(report: ModelPoisoningReport) -> str:
    lines = [f"Model Poisoning Detection Report", f"{'=' * 40}"]
    lines.append(f"Total patterns: {report.total_patterns}")
    lines.append(f"Total agents: {report.total_agents}")
    lines.append("")

    if report.chains:
        lines.append("POISONING CHAINS (critical):")
        for c in report.chains:
            lines.append(f"  {c['description']}")
        lines.append("")

    for s in report.agent_summaries:
        lines.append(f"Agent: {s.agent_id}")
        lines.append(f"  Patterns: {s.total_patterns}")
        for t, cnt in sorted(s.by_type.items()):
            lines.append(f"    {t}: {cnt}")
        if s.has_chain:
            lines.append("  ** CHAIN DETECTED **")
        lines.append("")

    return "\n".join(lines)


def format_json(report: ModelPoisoningReport) -> str:
    return json.dumps(asdict(report), indent=2, default=str)


def _load_events(evidence_dir: Path) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    if not evidence_dir.is_dir():
        return result
    for f in sorted(evidence_dir.iterdir()):
        if f.suffix == ".json" and f.is_file():
            try:
                data = json.loads(f.read_text())
                if isinstance(data, list):
                    result[f.name] = data
                elif isinstance(data, dict):
                    result[f.name] = [data]
            except (json.JSONDecodeError, OSError):
                pass
    return result
