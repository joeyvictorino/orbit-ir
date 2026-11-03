"""Phishing kit detection for agent incident reconstruction.

Detects patterns where agents deploy or operate phishing infrastructure:
- credential_harvest_page: fake login page deployment for credential theft
- email_spoof_campaign: spoofed email sending with phishing lures
- domain_typosquat_setup: lookalike domain registration for phishing
- kit_deployment: phishing kit archive extraction and setup
- redirect_chain: multi-hop URL redirect chains to phishing pages
- brand_impersonation: impersonation of legitimate brand assets and logos
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "credential_harvest_page": {
        "patterns": [
            r"(?i)(credential|password|login)\s+(harvest|collect|capture|steal|phish)\w*\s+(page|form|site|portal)\w*",
            r"(?i)(fake|spoof|clone|replica)\w*\s+(login|signin|auth)\w*\s+(page|form|portal|site)\w*",
            r"(?i)(deploy|host|serv|creat)\w*\s+(fake|phish|spoof)\w*\s+(login|credential|auth)\w*\s+(page|form|site)\w*",
            r"(?i)(credential|password)\s+(phish|harvest|intercept|capture)\w*\s+(form|page|endpoint)\w*",
        ],
        "severity": "critical",
        "description": "Fake login page deployment for credential theft",
    },
    "email_spoof_campaign": {
        "patterns": [
            r"(?i)(spoof|forg|fake)\w*\s+(email|message|mail)\s+(send|campaign|blast|deliver)\w*",
            r"(?i)(phishing|spear.phish|spearphish)\s+(email|campaign|message|lure)\w*\s+(send|deliver|distribut)\w*",
            r"(?i)(send|deliver|distribut)\w*\s+(phish|spoof|forg)\w*\s+(email|message|mail)\w*",
            r"(?i)(smtp|mail)\s+(spoof|relay|inject)\w*\s+(phish|lure|campaign|attack)\w*",
        ],
        "severity": "critical",
        "description": "Spoofed email sending with phishing lures",
    },
    "domain_typosquat_setup": {
        "patterns": [
            r"(?i)(typosquat|lookalike|homoglyph|doppelgang)\w*\s+(domain|url|site|registr)\w*",
            r"(?i)(register|setup|creat|acquir)\w*\s+(typosquat|lookalike|similar|confus)\w*\s+(domain|url|site)\w*",
            r"(?i)(domain|url|site)\s+(typosquat|impersonat|lookalike|spoof|mimic)\w*\s+(register|setup|deploy)\w*",
            r"(?i)(punycode|idn|homograph)\s+(attack|domain|registr)\w*\s+(phish|spoof|trick)\w*",
        ],
        "severity": "high",
        "description": "Lookalike domain registration for phishing",
    },
    "kit_deployment": {
        "patterns": [
            r"(?i)(phish|phishing)\s+(kit|toolkit|pack|archive)\s+(deploy|extract|instal|upload|unpack)\w*",
            r"(?i)(deploy|extract|instal|upload|unpack)\w*\s+(phish|phishing)\s+(kit|toolkit|pack|archive)\w*",
            r"(?i)(phish|phishing)\s+(infrastructure|server|site)\s+(setup|deploy|configur|provision)\w*",
            r"(?i)(kit|toolkit)\s+(extract|deploy|upload)\w*\s+(web|server|hosting|site)\w*",
        ],
        "severity": "high",
        "description": "Phishing kit archive extraction and setup",
    },
    "redirect_chain": {
        "patterns": [
            r"(?i)(redirect|forward)\s+(chain|hop|sequence|cascade)\s+(to|toward)\s+(phish|fake|malicious|harvest)\w*",
            r"(?i)(multi.hop|multi.stage|chain)\w*\s+(redirect|forward|url)\w*\s+(phish|malicious|credential)\w*",
            r"(?i)(url|link)\s+(redirect|shortener|obfuscat)\w*\s+(chain|phish|malicious|disguise)\w*",
            r"(?i)(phish|malicious)\s+(redirect|forward|bounce)\s+(chain|sequence|path|route)\w*",
        ],
        "severity": "medium",
        "description": "Multi-hop URL redirect chains to phishing pages",
    },
    "brand_impersonation": {
        "patterns": [
            r"(?i)(impersonat|mimic|clone|copy|replcat)\w*\s+(brand|company|organization|corpor)\w*\s+(logo|asset|page|site|identity)\w*",
            r"(?i)(brand|logo|identity|trademark)\s+(impersonat|spoof|clone|copy|steal|misus)\w*",
            r"(?i)(fake|counterfeit|fraudulent)\s+(brand|logo|corporate|company)\s+(page|site|email|asset)\w*",
            r"(?i)(clone|replicate|copy)\w*\s+(corporate|brand|official)\s+(website|page|portal|login)\w*",
        ],
        "severity": "high",
        "description": "Impersonation of legitimate brand assets and logos",
    },
}


@dataclass
class PhishingEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_brand: str = ""
    target_url: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[PhishingEvent] = field(default_factory=list)


@dataclass
class AttackChain:
    agent: str = ""
    steps: list[PhishingEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    chain_score: float = 0.0


@dataclass
class PhishingReport:
    total_events: int = 0
    phishing_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(credential.harvest|phish|spear.phish|email.spoof|"
    r"typosquat|lookalike|phishing.kit|redirect.chain|"
    r"brand.impersonat|login.spoof|smtp.spoof)\b"
)


def classify_event(event: dict) -> dict:
    text = " ".join(str(v) for v in event.values())
    best_cat = ""
    best_confidence = 0.0
    indicators: list[str] = []

    for cat in CATEGORIES:
        match_count = 0
        for pat in _get_patterns(cat):
            if pat.search(text):
                match_count += 1
        if match_count > 0:
            confidence = min(1.0, match_count * 0.3)
            if confidence > best_confidence:
                best_confidence = confidence
                best_cat = cat
            indicators.append(cat)

    return {
        "category": best_cat,
        "confidence": round(best_confidence, 2),
        "indicators": indicators,
    }


def analyze(events: list[dict]) -> dict:
    report = PhishingReport(total_events=len(events))
    cat_events: dict[str, list[PhishingEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        result = classify_event(ev)
        if result["category"]:
            report.phishing_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            pe = PhishingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_brand=str(ev.get("target_brand", ev.get("brand", ""))),
                target_url=str(ev.get("target_url", ev.get("url", ""))),
                raw=ev,
            )
            cat_events[cat].append(pe)
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

    severity_weight = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}
    total_weighted = 0.0
    for cs in report.categories:
        total_weighted += cs.count * severity_weight.get(cs.severity, 0.3)

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
    report.attack_chains = _detect_chains(events)

    return _report_to_dict(report)


def _detect_chains(events: list[dict]) -> list[AttackChain]:
    agent_events: dict[str, list[PhishingEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        result = classify_event(ev)
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            pe = PhishingEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(pe)

    chains = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            chains.append(AttackChain(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                chain_score=round(score, 2),
            ))
    return chains[:20]


def load_events(path: str) -> list[dict]:
    events: list[dict] = []
    p = Path(path)
    if not p.exists():
        return events
    if p.is_file() and p.suffix == ".json":
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, list):
                events.extend(data)
            elif isinstance(data, dict):
                events.append(data)
        except (json.JSONDecodeError, OSError):
            pass
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


def _report_to_dict(report: PhishingReport) -> dict:
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
    for chain in data.get("attack_chains", []):
        for step in chain.get("steps", []):
            step.pop("raw", None)
    return data


def format_report(analysis: dict) -> str:
    lines = [
        "Phishing Kit Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"Phishing events: {analysis.get('phishing_events', 0)}",
        f"Risk score: {analysis.get('risk_score', 0):.2f} ({analysis.get('risk_level', 'none')})",
        f"Agents involved: {len(analysis.get('agents_involved', []))}",
        "",
    ]

    for cs in analysis.get("categories", []):
        if cs["count"] > 0:
            lines.append(f"  {cs['category']:<30s}  {cs['count']:>3d} events  severity={cs['severity']}")
            lines.append(f"    {cs['description']}")

    chains = analysis.get("attack_chains", [])
    if chains:
        lines.append("")
        lines.append("Attack chains:")
        for c in chains[:10]:
            lines.append(
                f"  Agent {c['agent']}: {len(c['steps'])} steps, "
                f"score={c['chain_score']:.2f}, "
                f"categories: {', '.join(c['categories_seen'])}"
            )

    lines.append("")
    return "\n".join(lines)
