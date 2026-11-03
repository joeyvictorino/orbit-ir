"""Brute force attack pattern detection for agent incident reconstruction.

Detects patterns where agents conduct brute force attacks:
- credential_spray: password spraying across multiple accounts
- dictionary_attack: dictionary-based credential guessing attempts
- rate_abuse: excessive authentication attempts exceeding rate limits
- token_brute: brute forcing API tokens, session IDs, or OTP codes
- account_lockout: triggering account lockout through repeated failures
- enumeration: user or resource enumeration through response timing/content
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "credential_spray": {
        "patterns": [
            r"(?i)(password|credential)\s+(spray|stuff|test|rotat)\w*\s+(across|against|on|multiple|many)\s+(account|user|target|endpoint)",
            r"(?i)(spray|rotat)\w*\s+(password|credential|auth)\w*\s+(across|against|multiple|many)",
            r"(?i)(common|default|weak|leaked|breach)\s+(password|credential)\w*\s+(list|set|collection|wordlist)\s+(against|across|on)",
            r"(?i)(credential\s+stuff|password\s+spray|pass.the.hash|auth\s+spray)",
        ],
        "severity": "critical",
        "description": "Password spraying across multiple accounts",
    },
    "dictionary_attack": {
        "patterns": [
            r"(?i)(dictionary|wordlist|rockyou|seclist)\s+(attack|brute|crack|guess|attempt)",
            r"(?i)(brute\s*force|crack|guess)\w*\s+(password|credential|passphrase|pin)\s+(using|with|from)\s+(dictionary|wordlist|list|file)",
            r"(?i)(john|hashcat|hydra|medusa|ncrack|patator)\s+(attack|crack|brute|run|start)",
            r"(?i)(password|login|auth)\w*\s+(attempt|try|guess)\w*\s+(from|using|with)\s+(list|file|dictionary|wordlist)",
        ],
        "severity": "high",
        "description": "Dictionary-based credential guessing attempts",
    },
    "rate_abuse": {
        "patterns": [
            r"(?i)(rate\s+limit|throttl)\w*\s+(exceed|bypass|evad|circumvent|violat|hit|trigger)",
            r"(?i)(excessive|rapid|burst|flood)\w*\s+(auth|login|request|attempt|connect)\w*\s+(attempt|request|call)",
            r"(?i)(too\s+many|excess)\s+(attempt|request|login|auth|fail)\w*\s+(detect|block|flag|alert|warn)",
            r"(?i)(auth|login|api)\w*\s+(flood|storm|barrage|bombardment|deluge)",
        ],
        "severity": "high",
        "description": "Excessive authentication attempts exceeding rate limits",
    },
    "token_brute": {
        "patterns": [
            r"(?i)(brute\s*force|enum|guess|crack|fuzz)\w*\s+(token|session\s+id|api\s+key|otp|mfa|totp|2fa|jwt)",
            r"(?i)(token|session|api.key|otp|mfa.code)\s+(brute|guess|enum|crack|fuzz|exhaust)\w*",
            r"(?i)(sequent|increm|itera)\w*\s+(token|session|nonce|id|code)\s+(test|check|try|attempt|guess)",
            r"(?i)(predict|forge|replay|tamper)\w*\s+(session|token|cookie|jwt|bearer)\s+(id|key|value|code)",
        ],
        "severity": "critical",
        "description": "Brute forcing API tokens, session IDs, or OTP codes",
    },
    "account_lockout": {
        "patterns": [
            r"(?i)(account|user)\s+(lock|block|disable|suspend)\w*\s+(trigger|caus|due\s+to|after|from)\s+(fail|attempt|brute|invalid)",
            r"(?i)(trigger|caus|forc)\w*\s+(account|user)\s+(lock|block|disable|suspend|freeze)",
            r"(?i)(lockout|lock.out|locked\s+out)\s+(policy|threshold|trigger|detect|event|alert)",
            r"(?i)(repeated|multiple|successive|consecutive)\s+(fail|invalid|wrong|incorrect)\s+(login|auth|password|attempt)",
        ],
        "severity": "high",
        "description": "Triggering account lockout through repeated failures",
    },
    "enumeration": {
        "patterns": [
            r"(?i)(user|account|email|username)\s+(enum|discover|harvest|collect|list)\w*\s+(via|through|using|by)\s+(response|timing|error|status|message)",
            r"(?i)(enum|discover)\w*\s+(valid|exist|active|registered)\s+(user|account|email|username)",
            r"(?i)(timing|response\s+time|status\s+code|error\s+message)\s+(side.channel|leak|reveal|disclose|expos)\w*\s+(user|account|exist)",
            r"(?i)(oracle|side.channel|information\s+leak)\w*\s+(user|account|credential|valid)\s+(enum|exist|discover)",
        ],
        "severity": "medium",
        "description": "User or resource enumeration through response timing/content",
    },
}


@dataclass
class BruteForceEvent:
    timestamp: str = ""
    agent_id: str = ""
    category: str = ""
    technique: str = ""
    detail: str = ""
    severity: str = "medium"
    target_account: str = ""
    attempt_count: int = 0
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[BruteForceEvent] = field(default_factory=list)


@dataclass
class AttackCampaign:
    agent: str = ""
    steps: list[BruteForceEvent] = field(default_factory=list)
    categories_seen: list[str] = field(default_factory=list)
    campaign_score: float = 0.0


@dataclass
class BruteForceReport:
    total_events: int = 0
    brute_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    agents_involved: list[str] = field(default_factory=list)
    attack_campaigns: list[AttackCampaign] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_TECHNIQUE_RE = re.compile(
    r"(?i)\b(credential.spray|password.spray|dictionary.attack|brute.force|"
    r"rate.limit|rate.abuse|token.brute|otp.brute|account.lockout|"
    r"user.enum|timing.attack|hydra|hashcat|medusa)\b"
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
    report = BruteForceReport(total_events=len(events))
    cat_events: dict[str, list[BruteForceEvent]] = {c: [] for c in CATEGORIES}
    agents_seen: set[str] = set()

    for ev in events:
        result = classify_event(ev)
        if result["category"]:
            report.brute_events += 1
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            bfe = BruteForceEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                target_account=str(ev.get("target", ev.get("account", ""))),
                attempt_count=int(ev.get("attempts", ev.get("count", 0)) or 0),
                raw=ev,
            )
            cat_events[cat].append(bfe)
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
    report.attack_campaigns = detect_campaigns(events)

    return _report_to_dict(report)


def detect_campaigns(events: list[dict]) -> list[AttackCampaign]:
    agent_events: dict[str, list[BruteForceEvent]] = defaultdict(list)
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        result = classify_event(ev)
        text = " ".join(str(v) for v in ev.values())
        for cat in result["indicators"]:
            t_match = _TECHNIQUE_RE.search(text)
            technique = t_match.group(1).lower() if t_match else ""
            bfe = BruteForceEvent(
                timestamp=str(ev.get("timestamp", "")),
                agent_id=agent,
                category=cat,
                technique=technique,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            agent_events[agent].append(bfe)

    campaigns = []
    for agent, sevents in sorted(agent_events.items()):
        if len(sevents) >= 2:
            cats = sorted(set(se.category for se in sevents))
            score = min(1.0, len(sevents) * 0.18)
            campaigns.append(AttackCampaign(
                agent=agent,
                steps=sevents[:10],
                categories_seen=cats,
                campaign_score=round(score, 2),
            ))
    return campaigns[:20]


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


def _report_to_dict(report: BruteForceReport) -> dict:
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
    for camp in data.get("attack_campaigns", []):
        for step in camp.get("steps", []):
            step.pop("raw", None)
    return data


def format_report(analysis: dict) -> str:
    lines = [
        "Brute Force Attack Analysis",
        "=" * 45,
        "",
        f"Total events: {analysis.get('total_events', 0)}",
        f"Brute force events: {analysis.get('brute_events', 0)}",
        f"Risk score: {analysis.get('risk_score', 0):.2f} ({analysis.get('risk_level', 'none')})",
        f"Agents involved: {len(analysis.get('agents_involved', []))}",
        "",
    ]

    for cs in analysis.get("categories", []):
        if cs["count"] > 0:
            lines.append(f"  {cs['category']:<30s}  {cs['count']:>3d} events  severity={cs['severity']}")
            lines.append(f"    {cs['description']}")

    campaigns = analysis.get("attack_campaigns", [])
    if campaigns:
        lines.append("")
        lines.append("Attack campaigns:")
        for c in campaigns[:10]:
            lines.append(
                f"  Agent {c['agent']}: {len(c['steps'])} steps, "
                f"score={c['campaign_score']:.2f}, "
                f"categories: {', '.join(c['categories_seen'])}"
            )

    lines.append("")
    return "\n".join(lines)
