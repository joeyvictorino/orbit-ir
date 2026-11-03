"""Token theft detection — identifies agent credential/token stealing patterns."""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


CATEGORIES = {
    "env_credential_access": {
        "label": "Environment Credential Access",
        "weight": 0.25,
        "patterns": [
            r"env.*secret.*access",
            r"read.*api[\s_-]*key",
            r"extract.*token.*env",
            r"environment.*credential.*dump",
            r"getenv.*secret",
        ],
    },
    "token_exfiltration": {
        "label": "Token Exfiltration",
        "weight": 0.25,
        "patterns": [
            r"token.*exfil",
            r"send.*credential.*external",
            r"upload.*token.*remote",
            r"transmit.*api[\s_-]*key",
            r"leak.*secret.*network",
        ],
    },
    "credential_file_read": {
        "label": "Credential File Read",
        "weight": 0.20,
        "patterns": [
            r"read.*\.aws.*credential",
            r"access.*kubeconfig",
            r"read.*\.ssh.*key",
            r"open.*credential.*file",
            r"parse.*secret.*config",
        ],
    },
    "token_replay": {
        "label": "Token Replay Attack",
        "weight": 0.15,
        "patterns": [
            r"replay.*token",
            r"reuse.*stolen.*credential",
            r"impersonat.*token",
            r"forged.*auth.*header",
            r"session.*hijack.*token",
        ],
    },
    "metadata_service_probe": {
        "label": "Metadata Service Credential Probe",
        "weight": 0.10,
        "patterns": [
            r"169\.254\.169\.254",
            r"metadata.*service.*token",
            r"imds.*credential",
            r"instance.*metadata.*role",
            r"cloud.*metadata.*secret",
        ],
    },
    "keychain_access": {
        "label": "Keychain/Vault Access",
        "weight": 0.05,
        "patterns": [
            r"keychain.*extract",
            r"vault.*secret.*read",
            r"credential.*store.*dump",
            r"password.*manager.*access",
            r"secret.*manager.*list",
        ],
    },
}


@dataclass
class CategoryCount:
    category: str
    label: str
    count: int = 0


@dataclass
class ChainStep:
    event_index: int
    category: str
    message: str


@dataclass
class Chain:
    agent: str
    steps: List[ChainStep] = field(default_factory=list)
    categories_seen: List[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class AnalysisResult:
    total_events: int = 0
    violation_events: int = 0
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: List[str] = field(default_factory=list)
    categories: List[CategoryCount] = field(default_factory=list)
    chains: List[Chain] = field(default_factory=list)


def _classify_event(event: Dict[str, Any]) -> List[Tuple[str, str]]:
    msg = event.get("message", "").lower()
    matches = []
    for cat, info in CATEGORIES.items():
        for pat in info["patterns"]:
            if re.search(pat, msg):
                matches.append((cat, info["label"]))
                break
    return matches


def _detect_chains(events: List[Dict[str, Any]]) -> List[Chain]:
    agent_events: Dict[str, List[Tuple[int, List[Tuple[str, str]]]]] = {}
    for i, ev in enumerate(events):
        matches = _classify_event(ev)
        if not matches:
            continue
        agent = ev.get("agent_id", "unknown")
        agent_events.setdefault(agent, []).append((i, matches))

    chains = []
    for agent, items in agent_events.items():
        if len(items) < 2:
            continue
        chain = Chain(agent=agent)
        cats_seen = set()
        for idx, matches in items:
            cat = matches[0][0]
            chain.steps.append(ChainStep(
                event_index=idx,
                category=cat,
                message=events[idx].get("message", ""),
            ))
            cats_seen.add(cat)
        chain.categories_seen = sorted(cats_seen)
        chain.violation_score = min(1.0, len(chain.steps) * 0.2 + len(cats_seen) * 0.15)
        chains.append(chain)
    return chains


def _load_events(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    files = list(p.glob("*.json")) if p.is_dir() else [p]
    events = []
    for f in files:
        try:
            data = json.loads(f.read_text())
            if isinstance(data, list):
                events.extend(data)
            elif isinstance(data, dict):
                events.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return events


def _compute_risk(total: int, violations: int, chains: List[Chain]) -> Tuple[float, str]:
    if violations == 0:
        return 0.0, "none"
    ratio = violations / max(total, 1)
    chain_boost = sum(c.violation_score for c in chains) * 0.1
    score = min(1.0, ratio * 2.0 + chain_boost)
    if score >= 0.7:
        level = "critical"
    elif score >= 0.4:
        level = "high"
    elif score >= 0.15:
        level = "medium"
    else:
        level = "low"
    return score, level


def analyze_token_theft(
    events_or_path: Union[List[Dict[str, Any]], str, Path],
) -> AnalysisResult:
    if isinstance(events_or_path, (str, Path)):
        events = _load_events(str(events_or_path))
    else:
        events = events_or_path

    result = AnalysisResult(total_events=len(events))
    cat_counts: Dict[str, int] = {c: 0 for c in CATEGORIES}
    agents = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            result.violation_events += 1
            agents.add(ev.get("agent_id", "unknown"))
            for cat, _ in matches:
                cat_counts[cat] += 1

    result.agents_involved = sorted(agents)
    result.categories = [
        CategoryCount(category=c, label=CATEGORIES[c]["label"], count=cat_counts[c])
        for c in CATEGORIES
    ]
    result.chains = _detect_chains(events)
    result.risk_score, result.risk_level = _compute_risk(
        result.total_events, result.violation_events, result.chains,
    )
    return result


def format_text(result: AnalysisResult) -> str:
    lines = [
        f"Token Theft Detection ({result.total_events} events, "
        f"{result.violation_events} violations)",
        f"  Risk score: {result.risk_score:.2f}  Level: {result.risk_level}",
        "",
    ]
    for c in result.categories:
        lines.append(f"  {c.label:40s} {c.count}")
    lines.append("")
    if result.chains:
        lines.append(f"  Violation chains: {len(result.chains)}")
        for ch in result.chains:
            lines.append(f"    Agent {ch.agent}: {len(ch.steps)} steps, "
                         f"score {ch.violation_score:.2f}")
    if result.agents_involved:
        lines.append(f"  Agents involved: {', '.join(result.agents_involved)}")
    return "\n".join(lines) + "\n"


def format_json(result: AnalysisResult) -> str:
    data = {
        "total_events": result.total_events,
        "violation_events": result.violation_events,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "agents_involved": result.agents_involved,
        "categories": [
            {"category": c.category, "label": c.label, "count": c.count}
            for c in result.categories
        ],
        "chains": [
            {
                "agent": ch.agent,
                "steps": [
                    {"event_index": s.event_index, "category": s.category}
                    for s in ch.steps
                ],
                "categories_seen": ch.categories_seen,
                "violation_score": ch.violation_score,
            }
            for ch in result.chains
        ],
    }
    return json.dumps(data, indent=2)
