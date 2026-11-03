"""Cryptocurrency mining detection — identifies agent crypto mining abuse patterns."""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


CATEGORIES = {
    "miner_binary": {
        "label": "Mining Binary Execution",
        "weight": 0.25,
        "patterns": [
            r"xmrig",
            r"cpuminer",
            r"minerd",
            r"mining[\s_-]*binary.*execut",
            r"cgminer",
        ],
    },
    "pool_connection": {
        "label": "Mining Pool Connection",
        "weight": 0.25,
        "patterns": [
            r"stratum\+tcp",
            r"mining[\s_-]*pool.*connect",
            r"pool\..*\.com.*3333",
            r"connect.*mining.*pool",
            r"stratum.*protocol",
        ],
    },
    "cpu_abuse": {
        "label": "CPU Resource Abuse",
        "weight": 0.20,
        "patterns": [
            r"cpu.*100.*percent",
            r"cpu.*usage.*spike.*sustain",
            r"all.*cores.*utiliz",
            r"process.*consuming.*cpu",
            r"high[\s_-]*cpu.*crypto",
        ],
    },
    "gpu_abuse": {
        "label": "GPU Resource Abuse",
        "weight": 0.10,
        "patterns": [
            r"gpu.*mining",
            r"cuda.*hash",
            r"opencl.*mining",
            r"gpu.*utilization.*100",
            r"graphics.*card.*crypto",
        ],
    },
    "crypto_wallet": {
        "label": "Cryptocurrency Wallet Reference",
        "weight": 0.10,
        "patterns": [
            r"wallet.*address.*0x[0-9a-f]",
            r"bitcoin.*address",
            r"monero.*wallet",
            r"crypto.*payout.*address",
            r"wallet.*[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
        ],
    },
    "stealth_mining": {
        "label": "Stealth Mining Technique",
        "weight": 0.10,
        "patterns": [
            r"throttle.*mining.*detect",
            r"hide.*miner.*process",
            r"stealth.*crypto.*min",
            r"disguise.*mining.*legitimate",
            r"process.*rename.*miner",
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


def analyze_crypto_mine(
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
        f"Crypto Mining Detection ({result.total_events} events, "
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
