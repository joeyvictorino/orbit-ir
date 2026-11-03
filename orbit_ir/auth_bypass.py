"""Authentication bypass detection for agent incident reconstruction.

Detects patterns where agents circumvent authentication mechanisms:
- token_replay: reuse of expired or revoked tokens
- session_fixation: forcing a known session ID on a victim
- auth_header_manipulation: tampering with authorization headers
- auth_downgrade: fallback to weaker authentication methods
- denied_then_success: denied auth followed by successful access via different path
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CATEGORIES = {
    "token_replay": {
        "patterns": [
            r"(?i)(replay|reuse|resubmit)\w*\s+\w*\s*(token|jwt|bearer|session.token|auth.token)",
            r"(?i)(expired|revoked|invalid)\s+(token|jwt|bearer)",
            r"(?i)token\s+(replay|reuse)",
            r"(?i)(stale|old|previous)\s+\w*\s*(token|jwt|bearer)",
            r"(?i)replay\s+attack",
        ],
        "severity": "critical",
        "description": "Reuse of expired or revoked authentication tokens",
    },
    "session_fixation": {
        "patterns": [
            r"(?i)session\s+(fixat|fix|forc|set|inject)",
            r"(?i)(set|inject|force)\s+session\s*(id|cookie|token)",
            r"(?i)PHPSESSID\s*=|JSESSIONID\s*=|connect\.sid\s*=",
            r"(?i)(pre-?set|predetermined)\s+session",
            r"(?i)session\s+(hijack|steal|takeover)",
        ],
        "severity": "critical",
        "description": "Forcing a known session ID to hijack authentication",
    },
    "auth_header_manipulation": {
        "patterns": [
            r"(?i)(manipulat|tamper|modif|forg)(e|ed|ing)\s+(auth|authorization)\s+header",
            r"(?i)Authorization:\s*(Bearer|Basic|Digest)\s+[a-zA-Z0-9+/=]{10,}",
            r"(?i)(craft|forge|fake)\w*\s+(jwt|token|bearer|auth)",
            r"(?i)X-Forwarded-For.*bypass",
            r"(?i)(spoof|fake)\w*\s+(header|identity|credential)",
        ],
        "severity": "high",
        "description": "Tampering with authorization headers",
    },
    "auth_downgrade": {
        "patterns": [
            r"(?i)(downgrad|fallback|switch)\w*\s+(to\s+)?(basic|plain|http|weak|none)\s*(auth|authentication)",
            r"(?i)(disabl|bypass|skip)(e|ed|ing)\s+(mfa|2fa|two.factor|multi.factor)",
            r"(?i)(remove|strip)\w*\s+(tls|ssl|https|encryption)",
            r"(?i)auth\w*\s+(downgrad|weaken)",
            r"(?i)(plain|clear)text\s+(password|credential|auth)",
        ],
        "severity": "high",
        "description": "Fallback to weaker authentication methods",
    },
    "denied_then_success": {
        "patterns": [
            r"(?i)(denied|rejected|forbidden|401|403).*\b(then|followed.by|subsequently)\b.*(success|allow|grant|200|accept)",
            r"(?i)(fail|denied)\s+auth.*alternate\s+(path|route|method|endpoint)",
            r"(?i)(bypass|circumvent|evad)(e|ed|ing)\s+(auth|login|access.control)",
            r"(?i)(unauthorized|unauthenticated)\s+access\s+(granted|succeeded|allowed)",
            r"(?i)(brute.?force|credential.?stuff|password.?spray)",
        ],
        "severity": "critical",
        "description": "Denied auth attempt followed by successful access through different path",
    },
}


@dataclass
class AuthEvent:
    timestamp: str = ""
    source: str = ""
    category: str = ""
    method: str = ""
    detail: str = ""
    severity: str = "medium"
    raw: dict = field(default_factory=dict)


@dataclass
class CategorySummary:
    category: str = ""
    description: str = ""
    count: int = 0
    severity: str = "medium"
    events: list[AuthEvent] = field(default_factory=list)


@dataclass
class AuthBypassReport:
    total_events: int = 0
    bypass_events: int = 0
    categories: list[CategorySummary] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "none"
    auth_methods_seen: list[str] = field(default_factory=list)
    denied_success_sequences: list[dict] = field(default_factory=list)


_COMPILED: dict[str, list[re.Pattern]] = {}


def _get_patterns(category: str) -> list[re.Pattern]:
    if category not in _COMPILED:
        _COMPILED[category] = [re.compile(p) for p in CATEGORIES[category]["patterns"]]
    return _COMPILED[category]


_AUTH_METHOD_RE = re.compile(
    r"(?i)\b(bearer|basic|digest|oauth|saml|kerberos|ntlm|api.key|jwt|mfa|2fa|openid|oidc)\b"
)


def _classify_event(event: dict) -> list[tuple[str, str]]:
    text = " ".join(str(v) for v in event.values())
    matches = []
    for cat, info in CATEGORIES.items():
        for pat in _get_patterns(cat):
            if pat.search(text):
                method_match = _AUTH_METHOD_RE.search(text)
                method = method_match.group(1).lower() if method_match else ""
                matches.append((cat, method))
                break
    return matches


def _detect_denied_success(events: list[dict]) -> list[dict]:
    sequences: list[dict] = []
    deny_re = re.compile(r"(?i)(denied|rejected|forbidden|401|403|fail|unauthorized)")
    success_re = re.compile(r"(?i)(success|allowed|granted|200|accepted|authenticated)")

    agent_denials: dict[str, list[dict]] = {}
    for ev in events:
        agent = str(ev.get("agent_id", ev.get("source", "")))
        text = " ".join(str(v) for v in ev.values())
        ts = str(ev.get("timestamp", ""))

        if deny_re.search(text):
            agent_denials.setdefault(agent, []).append({"timestamp": ts, "detail": text[:200]})
        elif success_re.search(text) and agent in agent_denials:
            for denial in agent_denials[agent]:
                if denial["timestamp"] <= ts:
                    sequences.append({
                        "agent": agent,
                        "denied_at": denial["timestamp"],
                        "succeeded_at": ts,
                        "denial_detail": denial["detail"],
                        "success_detail": text[:200],
                    })
                    break

    return sequences[:20]


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


def analyze_auth_bypass(events_or_dir: str | Path | list[dict]) -> AuthBypassReport:
    if isinstance(events_or_dir, list):
        return _analyze(events_or_dir)
    evidence_dir = str(events_or_dir)
    events = _load_events(evidence_dir)
    return _analyze(events)


def _analyze(events: list[dict]) -> AuthBypassReport:
    report = AuthBypassReport(total_events=len(events))

    cat_events: dict[str, list[AuthEvent]] = {c: [] for c in CATEGORIES}
    methods_seen: set[str] = set()

    for ev in events:
        matches = _classify_event(ev)
        if matches:
            report.bypass_events += 1
        for cat, method in matches:
            e = AuthEvent(
                timestamp=str(ev.get("timestamp", "")),
                source=str(ev.get("source", ev.get("agent_id", ""))),
                category=cat,
                method=method,
                detail=str(ev.get("detail", ev.get("message", "")))[:200],
                severity=CATEGORIES[cat]["severity"],
                raw=ev,
            )
            cat_events[cat].append(e)
            if method:
                methods_seen.add(method)

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

    report.auth_methods_seen = sorted(methods_seen)
    report.denied_success_sequences = _detect_denied_success(events)

    return report


def format_text(report: AuthBypassReport) -> str:
    lines = [
        "Authentication Bypass Analysis",
        "=" * 45,
        "",
        f"Total events: {report.total_events}",
        f"Bypass events: {report.bypass_events}",
        f"Risk score: {report.risk_score:.2f} ({report.risk_level})",
        "",
    ]

    for cs in report.categories:
        if cs.count > 0:
            lines.append(f"  {cs.category:<30s}  {cs.count:>3d} events  severity={cs.severity}")
            lines.append(f"    {cs.description}")

    if report.auth_methods_seen:
        lines.append("")
        lines.append(f"Auth methods seen: {', '.join(report.auth_methods_seen)}")

    if report.denied_success_sequences:
        lines.append("")
        lines.append("Denied-then-success sequences:")
        for seq in report.denied_success_sequences[:5]:
            lines.append(f"  Agent {seq['agent']}: denied {seq['denied_at']} -> success {seq['succeeded_at']}")

    lines.append("")
    return "\n".join(lines)


def format_json(report: AuthBypassReport) -> str:
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
    return json.dumps(data, indent=2, default=str)
