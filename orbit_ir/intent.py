"""Classify agent intent from action sequences using pattern matching."""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


_RECON_ACTIONS = frozenset({
    "list", "scan", "enumerate", "discover", "probe", "ping",
    "nslookup", "whois", "traceroute", "fingerprint", "detect",
    "query", "search", "find", "lookup",
})

_RECON_RESOURCES = frozenset({
    "hosts", "ports", "services", "endpoints", "users", "roles",
    "iam", "network", "dns", "infrastructure",
})

_DATA_COLLECTION_ACTIONS = frozenset({
    "read", "get", "fetch", "download", "dump", "extract",
    "read_file", "read_config", "get_secret", "describe",
})

_DATA_COLLECTION_RESOURCES = frozenset({
    "config", "credentials", "secrets", "keys", "tokens",
    "database", "tables", "users", "env", "environment",
})

_EXPLOITATION_ACTIONS = frozenset({
    "create_role", "modify_role", "assign_role", "grant_permission",
    "create_credential", "create_token", "modify_policy", "elevate",
    "escalate", "bypass", "inject", "exploit", "override",
})

_EXPLOITATION_EFFECTS = frozenset({
    "privilege-escalated", "policy-modified", "role-modified",
    "permission-granted", "access-control-modified", "bypassed",
})

_EXFILTRATION_ACTIONS = frozenset({
    "upload", "send", "post", "transfer", "export", "email",
    "write_external", "push", "publish", "transmit",
})

_EXFILTRATION_INDICATORS = frozenset({
    "external", "outbound", "egress", "remote", "cloud",
    "s3", "blob", "bucket", "webhook",
})

_CLEANUP_ACTIONS = frozenset({
    "delete", "remove", "clear", "purge", "wipe", "truncate",
    "rotate", "destroy", "clean", "erase",
})

_CLEANUP_RESOURCES = frozenset({
    "log", "logs", "audit", "history", "trace", "evidence",
    "record", "journal", "syslog",
})

INTENT_CATEGORIES = [
    "reconnaissance",
    "data_collection",
    "exploitation",
    "exfiltration",
    "cleanup",
    "legitimate",
]


@dataclass
class IntentSignal:
    category: str
    action: str
    resource: str
    confidence: float
    reason: str


@dataclass
class IntentClassification:
    agent_id: str
    primary_intent: str
    confidence: float
    event_count: int
    signals: list[IntentSignal] = field(default_factory=list)
    intent_scores: dict[str, float] = field(default_factory=dict)


@dataclass
class IntentReport:
    total_agents: int
    classifications: list[IntentClassification] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    p = Path(path)
    if p.is_file():
        files = [p]
    else:
        files = sorted(p.glob("*.jsonl")) + sorted(p.glob("*.json"))
    for f in files:
        text = f.read_text(encoding="utf-8").strip()
        if not text:
            continue
        if f.suffix == ".jsonl" or "\n" in text:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        else:
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    events.extend(data)
                elif isinstance(data, dict):
                    events.append(data)
            except json.JSONDecodeError:
                continue
    return events


def _action_lower(event: dict[str, Any]) -> str:
    return str(event.get("actual_tool",
                         event.get("tool_name",
                                   event.get("action",
                                             event.get("type", ""))))).lower()


def _resource_lower(event: dict[str, Any]) -> str:
    return str(event.get("resource",
                         event.get("endpoint", ""))).lower()


def _effect_lower(event: dict[str, Any]) -> str:
    return str(event.get("effect", event.get("result", ""))).lower()


def _match_set(value: str, keywords: frozenset[str]) -> bool:
    return any(kw in value for kw in keywords)


def _classify_event(event: dict[str, Any]) -> list[IntentSignal]:
    action = _action_lower(event)
    resource = _resource_lower(event)
    effect = _effect_lower(event)
    raw_action = event.get("actual_tool", event.get("tool_name", event.get("action", "")))
    raw_resource = event.get("resource", event.get("endpoint", ""))
    signals: list[IntentSignal] = []

    if _match_set(action, _RECON_ACTIONS) or _match_set(resource, _RECON_RESOURCES):
        conf = 0.7
        if _match_set(action, _RECON_ACTIONS) and _match_set(resource, _RECON_RESOURCES):
            conf = 0.9
        signals.append(IntentSignal(
            category="reconnaissance", action=raw_action, resource=raw_resource,
            confidence=conf, reason=f"action/resource matches reconnaissance pattern",
        ))

    if _match_set(action, _DATA_COLLECTION_ACTIONS) or _match_set(resource, _DATA_COLLECTION_RESOURCES):
        conf = 0.6
        if _match_set(action, _DATA_COLLECTION_ACTIONS) and _match_set(resource, _DATA_COLLECTION_RESOURCES):
            conf = 0.85
        signals.append(IntentSignal(
            category="data_collection", action=raw_action, resource=raw_resource,
            confidence=conf, reason=f"action/resource matches data collection pattern",
        ))

    if _match_set(action, _EXPLOITATION_ACTIONS) or _match_set(effect, _EXPLOITATION_EFFECTS):
        conf = 0.8
        if _match_set(action, _EXPLOITATION_ACTIONS) and _match_set(effect, _EXPLOITATION_EFFECTS):
            conf = 0.95
        signals.append(IntentSignal(
            category="exploitation", action=raw_action, resource=raw_resource,
            confidence=conf, reason=f"action/effect matches exploitation pattern",
        ))

    if _match_set(action, _EXFILTRATION_ACTIONS) or _match_set(resource, _EXFILTRATION_INDICATORS):
        conf = 0.75
        if _match_set(action, _EXFILTRATION_ACTIONS) and _match_set(resource, _EXFILTRATION_INDICATORS):
            conf = 0.9
        signals.append(IntentSignal(
            category="exfiltration", action=raw_action, resource=raw_resource,
            confidence=conf, reason=f"action/resource matches exfiltration pattern",
        ))

    if _match_set(action, _CLEANUP_ACTIONS):
        conf = 0.65
        if _match_set(resource, _CLEANUP_RESOURCES):
            conf = 0.9
        signals.append(IntentSignal(
            category="cleanup", action=raw_action, resource=raw_resource,
            confidence=conf, reason=f"action matches cleanup pattern",
        ))

    if not signals:
        signals.append(IntentSignal(
            category="legitimate", action=raw_action, resource=raw_resource,
            confidence=0.5, reason="no suspicious pattern matched",
        ))

    return signals


class IntentClassifier:
    def __init__(self, min_confidence: float = 0.5):
        self.min_confidence = min_confidence

    def classify(self, evidence_dir: str | Path,
                 agent_id: str | None = None) -> IntentReport:
        path = Path(evidence_dir)
        events = _load_events(path)
        if agent_id:
            events = [e for e in events
                      if e.get("agent_id", e.get("agent", "")) == agent_id]

        by_agent: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for ev in events:
            agent = ev.get("agent_id", ev.get("agent", "unknown"))
            by_agent[agent].append(ev)

        classifications: list[IntentClassification] = []
        summary: dict[str, int] = defaultdict(int)

        for agent, agent_events in sorted(by_agent.items()):
            all_signals: list[IntentSignal] = []
            for ev in agent_events:
                all_signals.extend(_classify_event(ev))

            cat_scores: dict[str, list[float]] = defaultdict(list)
            for sig in all_signals:
                cat_scores[sig.category].append(sig.confidence)

            intent_scores: dict[str, float] = {}
            for cat in INTENT_CATEGORIES:
                scores = cat_scores.get(cat, [])
                if scores:
                    intent_scores[cat] = round(sum(scores) / len(scores), 3)
                else:
                    intent_scores[cat] = 0.0

            weighted: dict[str, float] = {}
            total_signals = len(all_signals) or 1
            for cat in INTENT_CATEGORIES:
                count = len(cat_scores.get(cat, []))
                avg = intent_scores.get(cat, 0.0)
                weighted[cat] = round(avg * (count / total_signals), 3)

            primary = max(weighted, key=lambda k: weighted[k])
            primary_conf = intent_scores.get(primary, 0.0)

            filtered = [s for s in all_signals if s.confidence >= self.min_confidence]

            classification = IntentClassification(
                agent_id=agent,
                primary_intent=primary,
                confidence=primary_conf,
                event_count=len(agent_events),
                signals=filtered,
                intent_scores=intent_scores,
            )
            classifications.append(classification)
            summary[primary] = summary.get(primary, 0) + 1

        return IntentReport(
            total_agents=len(classifications),
            classifications=classifications,
            summary=dict(summary),
        )


def classify_intents(evidence_dir: str | Path,
                     agent_id: str | None = None,
                     min_confidence: float = 0.5) -> IntentReport:
    return IntentClassifier(min_confidence).classify(evidence_dir, agent_id)


def format_intent_text(report: IntentReport) -> str:
    lines: list[str] = []
    lines.append("Intent Classification Report")
    lines.append(f"  Agents analyzed: {report.total_agents}")
    if report.summary:
        lines.append(f"  Intent distribution: {', '.join(f'{k}={v}' for k, v in sorted(report.summary.items()))}")
    lines.append("")

    for cls in report.classifications:
        lines.append(f"Agent: {cls.agent_id}")
        lines.append(f"  Primary intent: {cls.primary_intent} (confidence: {cls.confidence:.2f})")
        lines.append(f"  Events: {cls.event_count}")
        lines.append(f"  Scores: {', '.join(f'{k}={v:.2f}' for k, v in sorted(cls.intent_scores.items()) if v > 0)}")
        if cls.signals:
            lines.append(f"  Key signals ({len(cls.signals)}):")
            shown = 0
            for sig in cls.signals:
                if shown >= 10:
                    lines.append(f"    ... and {len(cls.signals) - 10} more")
                    break
                lines.append(f"    [{sig.category}] {sig.action} on {sig.resource} ({sig.confidence:.2f}) - {sig.reason}")
                shown += 1
        lines.append("")

    return "\n".join(lines)


def format_intent_json(report: IntentReport) -> str:
    return json.dumps(asdict(report), sort_keys=True, indent=2)
