"""Adversarial input detection for agent incident reconstruction.

Detects patterns where agents craft or deliver adversarial inputs designed
to manipulate AI model behavior:
- perturbation_craft: crafting adversarial perturbations to mislead models
- evasion_attack: modifying inputs to evade model detection/classification
- poisoning_input: injecting poisoned samples to corrupt model behavior
- trigger_injection: embedding hidden triggers for backdoor activation
- transferability_exploit: using transferable adversarial examples across models
- robustness_probe: systematically probing model robustness boundaries
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "perturbation_craft": {
        "patterns": [
            r"(?i)(craft|generat|creat|comput|optimiz)\w*\s+(adversarial\s+)?(perturbation|noise|distortion|modification)\s+(to|for|that|which)\s+(mislead|fool|deceiv|trick|confus)",
            r"(?i)(adversarial\s+)?(perturbation|noise|distortion)\s+(craft|generat|creat|comput|optimiz|appli)\w*\s*(to|for|against|on)\s*(model|classifier|detector|target)?",
            r"(?i)(fgsm|pgd|c&w|carlini|deepfool|autoattack|autopgd)\s+(attack|generat|perturbation|crafted|applied)",
            r"(?i)(minimiz|optimiz)\w*\s+(adversarial\s+)?(perturbation|distortion|noise)\s+(while|to)\s+(maintain|preserv|maximiz)\w*\s+(misclassif|evasion|attack)",
        ],
        "severity": "high",
        "description": "Crafting adversarial perturbations to mislead AI models",
    },
    "evasion_attack": {
        "patterns": [
            r"(?i)(modif|alter|transform|perturb|manipulat)\w*\s+(input|sample|example|data|query)\s+(to|for)\s+(evade|bypass|avoid|escape|circumvent)\s+(model|detect|classif|filter)",
            r"(?i)(evasion|bypass|avoidance)\s+(attack|technique|method|strategy)\s+(against|on|for|targeting)\s+(model|classifier|detector|filter)",
            r"(?i)(evad|bypass|avoid|escape|circumvent)\w*\s+(model|classifier|detector|filter|safety|guard|moderat)\w*\s+(using|via|through|with)\s+(adversarial|crafted|modified|perturbed)",
            r"(?i)(adversarial\s+)?(example|sample|input)\s+(design|craft|optimiz)\w*\s+(to|for)\s+(evad|bypass|avoid|escape)\s+(detect|classif|filter|safety|moderat)",
        ],
        "severity": "critical",
        "description": "Modifying inputs to evade model detection or classification",
    },
    "poisoning_input": {
        "patterns": [
            r"(?i)(inject|insert|introduc|plant|embed)\w*\s+(poison|corrupt|malicious|tainted|adversarial)\w*\s+(sample|data|input|example|training)\s*(into|to|for|in)?\s*(model|dataset|training|pipeline)?",
            r"(?i)(poison|corrupt|taint|contaminate)\w*\s+(training|dataset|data|input|sample)\s+(with|using|via|through)\s+(adversarial|malicious|crafted|manipulated)",
            r"(?i)(data\s+)?(poisoning|corruption|contamination)\s+(attack|technique|campaign)\s+(against|on|targeting|for)\s+(model|dataset|training|pipeline)",
            r"(?i)(backdoor|trojan)\s+(poison|inject|embed|plant|insert)\w*\s+(in|into|during|via)\s+(training|dataset|model|fine.?tun)",
        ],
        "severity": "critical",
        "description": "Injecting poisoned samples to corrupt model behavior",
    },
    "trigger_injection": {
        "patterns": [
            r"(?i)(inject|embed|insert|plant|hid)\w*\s+(hidden\s+)?(trigger|pattern|signal|watermark|patch)\s+(for|to|that|which)\s+(activat|backdoor|trigger|control|manipulat)",
            r"(?i)(backdoor|trojan)\s+(trigger|pattern|signal|activation)\s+(inject|embed|insert|plant|hid)\w*\s*(in|into|within|inside)?\s*(model|input|data|sample)?",
            r"(?i)(activat|fire|trigger)\w*\s+(hidden|embedded|planted|injected)\s+(backdoor|trojan|trigger|pattern)\s+(in|within|inside)\s+(model|network|classifier)",
            r"(?i)(hidden|covert|stealth)\s+(trigger|pattern|signal)\s+(that\s+)?(activat|caus|induc)\w*\s+(specific|targeted|malicious|unintended)\s+(behavio|output|response|classif)",
        ],
        "severity": "critical",
        "description": "Embedding hidden triggers for backdoor activation in models",
    },
    "transferability_exploit": {
        "patterns": [
            r"(?i)(transfer|port|migrat)\w*\s+(adversarial\s+)?(example|perturbation|attack|sample)\s+(from|across|between)\s+(model|source|surrogate)\s+(to|targeting|against)\s+(target|victim|different|another)",
            r"(?i)(adversarial\s+)?(transferab|cross.?model|black.?box)\w*\s+(attack|exploit|technique|example)\s+(using|via|through|from)\s+(surrogate|substitute|source|local)",
            r"(?i)(surrogate|substitute|shadow|proxy)\s+(model\s+)?(attack|technique|used|craft|generat)\w*\s+(to\s+)?(transfer|target|attack|exploit|fool|mislead)",
            r"(?i)(exploit|leverag|abus)\w*\s+(transferab|cross.?model)\w*\s+(of\s+)?(adversarial\s+)?(example|perturbation|attack|sample)\s*(across|between|to)?\s*(model|system)?",
        ],
        "severity": "high",
        "description": "Using transferable adversarial examples across different models",
    },
    "robustness_probe": {
        "patterns": [
            r"(?i)(systematic|automat|iterativ)\w*\s+(prob|test|evaluat|assess|explor)\w*\s+(model|classifier|detector)\s*(robust|vulnerab|weakness|boundary|limit)",
            r"(?i)(robustness|boundary|limit|weakness)\s+(prob|test|evaluat|scan|assess|explor)\w*\s+(of|on|against|for)\s+(model|classifier|detector|target)",
            r"(?i)(find|discover|identify|map|enumerat)\w*\s+(adversarial\s+)?(decision\s+)?(boundary|region|space|weak|blind)\w*\s*(of|in|for)?\s*(model|classifier|detector)?",
            r"(?i)(adaptive|query.based|black.?box)\s+(attack|prob|strateg|technique)\s+(to|for|that)\s+(find|discover|exploit|map)\s+(vulnerab|weakness|boundary|blind.?spot)",
        ],
        "severity": "high",
        "description": "Systematically probing model robustness boundaries for vulnerabilities",
    },
}


@dataclass
class AdversarialEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    policy_ref: str = ""
    violation_type: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[AdversarialEvent] = field(default_factory=list)


@dataclass
class AdversarialChain:
    agent: str = ""
    steps: list[AdversarialEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    violation_score: float = 0.0


@dataclass
class AdversarialReport:
    total_events: int = 0
    violation_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    violation_chains: list[AdversarialChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(fgsm|pgd|carlini|deepfool|autoattack|autopgd|"
    r"adversarial.?perturbation|evasion.?attack|data.?poison|"
    r"backdoor.?trigger|transfer.?attack|robustness.?prob)\b"
)


def _classify_event(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat in CATEGORIES:
        for pat in _get_patterns(cat):
            if pat.search(text):
                t_match = _TECHNIQUE_RE.search(text)
                technique = t_match.group(1).lower() if t_match else ""
                matches.append((cat, technique))
                break
    return matches


def _detect_chains(events: list[dict]) -> list[AdversarialChain]:
    agent_events: dict[str, list[AdversarialEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        matches = _classify_event(ev)
        for cat, technique in matches:
            ve = AdversarialEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                policy_ref=str(ev.get("policy_ref", ev.get("policy", ""))),
                violation_type=str(ev.get("violation_type", "")),
                raw=ev,
            )
            agent_events[agent].append(ve)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(AdversarialChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                violation_score=round(score, 2),
            ))
    return chains[:20]


def _load_events(evidence_dir: str) -> list[dict]:
    events: list[dict] = []
    p = Path(evidence_dir)
    if not p.exists():
        return events
    for f in sorted(p.iterdir()):
        if f.suffix == ".json":
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    events.extend(data)
                elif isinstance(data, dict):
                    events.append(data)
            except (json.JSONDecodeError, OSError):
                pass
    return events


_SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}


def analyze_adversarial_input(events_or_dir: str | Path | list[dict]) -> AdversarialReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    return _analyze(_load_events(str(events_or_dir)))


def _analyze(events: list[dict]) -> AdversarialReport:
    report = AdversarialReport(total_events=len(events))
    cat_events: dict[str, list[AdversarialEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.violation_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        for cat, technique in matches:
            e = AdversarialEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                policy_ref=str(ev.get("policy_ref", ev.get("policy", ""))),
                violation_type=str(ev.get("violation_type", "")),
                raw=ev,
            )
            cat_events[cat].append(e)
            if agent:
                agents_seen.add(agent)

    for cat, info in CATEGORIES.items():
        evts = cat_events[cat]
        report.categories.append(CategorySummary(
            category=cat,
            description=info["description"],
            count=len(evts),
            severity=info["severity"],
            events=evts[:10],
        ))

    total_weighted = 0.0
    for cs in report.categories:
        total_weighted += cs.count * _SEVERITY_WEIGHT.get(cs.severity, 0.3)

    if report.total_events > 0:
        report.risk_score = min(1.0, round(total_weighted / report.total_events, 2))

    if report.risk_score >= 0.5:
        report.risk_level = "critical"
    elif report.risk_score >= 0.3:
        report.risk_level = "high"
    elif report.risk_score >= 0.1:
        report.risk_level = "medium"
    elif report.risk_score > 0:
        report.risk_level = "low"
    else:
        report.risk_level = "none"

    report.agents_involved = sorted(agents_seen)
    report.violation_chains = _detect_chains(events)
    return report


def format_text(report: AdversarialReport) -> str:
    lines = [
        "Adversarial Input Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Violation events: {report.violation_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        f"Agents involved: {len(report.agents_involved)}",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.violation_chains:
        lines.append("")
        lines.append("Violation chains:")
        for c in report.violation_chains[:10]:
            lines.append(f"  Agent {c.agent}: {len(c.steps)} steps, score={c.violation_score:.2f}, categories: {', '.join(c.categories_seen)}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: AdversarialReport) -> str:
    def to_dict(obj: Any) -> Any:
        if hasattr(obj, "__dataclass_fields__"):
            d = {}
            for k in obj.__dataclass_fields__:
                val = getattr(obj, k)
                if isinstance(val, list):
                    d[k] = [to_dict(v) if hasattr(v, "__dataclass_fields__") else v for v in val]
                else:
                    d[k] = val
            return d
        return obj

    data = to_dict(report)
    for cs in data.get("categories", []):
        for ev in cs.get("events", []):
            ev.pop("raw", None)
    for chain in data.get("violation_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return json.dumps(data, indent=2, default=str)
