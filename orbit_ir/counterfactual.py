"""What-if scenario analysis for incident response.

Given detected incidents, models alternative outcomes by estimating
which subsequent events would not have occurred under different
mitigation scenarios (credential rotation, network segmentation,
access control).
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


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


def _parse_ts(val: str | None) -> datetime | None:
    if not val:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(val, fmt)
        except (ValueError, TypeError):
            continue
    return None


_CREDENTIAL_KEYWORDS = frozenset([
    "credential", "token", "api_key", "secret", "password", "auth",
    "login", "session", "cookie", "bearer", "oauth",
])

_LATERAL_KEYWORDS = frozenset([
    "lateral", "pivot", "move", "hop", "spread", "propagat",
    "remote_exec", "ssh", "rdp",
])

_ACCESS_KEYWORDS = frozenset([
    "unauthorized", "forbidden", "denied", "escalat", "privilege",
    "admin", "root", "sudo", "bypass", "exfiltrat",
])


def _event_matches_keywords(event: dict[str, Any], keywords: frozenset[str]) -> bool:
    text = json.dumps(event).lower()
    return any(kw in text for kw in keywords)


@dataclass
class ScenarioDefinition:
    name: str
    description: str
    keywords: list[str] = field(default_factory=list)
    event_types: list[str] = field(default_factory=list)

    def matches_event(self, event: dict[str, Any]) -> bool:
        kw_set = frozenset(k.lower() for k in self.keywords)
        if kw_set and _event_matches_keywords(event, kw_set):
            return True
        if self.event_types:
            etype = str(event.get("type", event.get("event_type", ""))).lower()
            if any(et.lower() in etype for et in self.event_types):
                return True
        return False


DEFAULT_SCENARIOS: list[ScenarioDefinition] = [
    ScenarioDefinition(
        name="credential_rotation",
        description="Credentials rotated immediately after initial compromise",
        keywords=list(_CREDENTIAL_KEYWORDS),
        event_types=["credential_reuse", "auth_failure", "token_theft"],
    ),
    ScenarioDefinition(
        name="network_segmentation",
        description="Network segmentation isolates lateral movement",
        keywords=list(_LATERAL_KEYWORDS),
        event_types=["lateral_movement", "network_scan", "port_scan"],
    ),
    ScenarioDefinition(
        name="access_control",
        description="Strict access controls prevent unauthorized actions",
        keywords=list(_ACCESS_KEYWORDS),
        event_types=["privilege_escalation", "unauthorized_access", "data_exfiltration"],
    ),
]


@dataclass
class CounterfactualResult:
    scenario: str
    description: str
    total_events: int
    prevented_events: int
    remaining_events: int
    reduction_pct: float
    prevented_event_ids: list[str] = field(default_factory=list)
    prevented_agents: list[str] = field(default_factory=list)
    timeline_impact: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_scenarios(path: str | Path | None) -> list[ScenarioDefinition]:
    if path is None:
        return list(DEFAULT_SCENARIOS)

    p = Path(path)
    if not p.exists():
        return list(DEFAULT_SCENARIOS)

    text = p.read_text(encoding="utf-8")

    if p.suffix in (".yaml", ".yml"):
        if not _HAS_YAML:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return list(DEFAULT_SCENARIOS)
        else:
            data = _yaml.safe_load(text)
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return list(DEFAULT_SCENARIOS)

    if not isinstance(data, dict) or "scenarios" not in data:
        return list(DEFAULT_SCENARIOS)

    scenarios: list[ScenarioDefinition] = []
    for s in data["scenarios"]:
        if not isinstance(s, dict) or "name" not in s:
            continue
        scenarios.append(ScenarioDefinition(
            name=s["name"],
            description=s.get("description", ""),
            keywords=s.get("keywords", []),
            event_types=s.get("event_types", []),
        ))
    return scenarios if scenarios else list(DEFAULT_SCENARIOS)


class CounterfactualAnalyzer:
    def __init__(self) -> None:
        pass

    def analyze(
        self,
        results: list[dict[str, Any]],
        evidence_dir: str | Path,
        scenarios: list[ScenarioDefinition] | None = None,
    ) -> list[dict[str, Any]]:
        evidence_dir = Path(evidence_dir)
        events = _load_events(evidence_dir) if evidence_dir.exists() else []

        all_events = list(events)
        for det in results:
            if det not in all_events:
                all_events.append(det)

        if scenarios is None:
            scenarios = list(DEFAULT_SCENARIOS)

        total = len(all_events)
        outputs: list[dict[str, Any]] = []

        for scenario in scenarios:
            prevented: list[dict[str, Any]] = []
            prevented_ids: list[str] = []
            prevented_agents: set[str] = set()

            for event in all_events:
                if scenario.matches_event(event):
                    prevented.append(event)
                    eid = event.get("id", event.get("event_id", event.get("detection_id", "")))
                    if eid:
                        prevented_ids.append(str(eid))
                    for key in ("agent_id", "agent", "src_agent", "dst_agent"):
                        v = event.get(key)
                        if isinstance(v, str) and v:
                            prevented_agents.add(v)

            prevented_count = len(prevented)
            remaining = total - prevented_count
            reduction = (prevented_count / total * 100.0) if total > 0 else 0.0

            if reduction >= 50:
                timeline_impact = "major"
            elif reduction >= 20:
                timeline_impact = "moderate"
            elif reduction > 0:
                timeline_impact = "minor"
            else:
                timeline_impact = "none"

            result = CounterfactualResult(
                scenario=scenario.name,
                description=scenario.description,
                total_events=total,
                prevented_events=prevented_count,
                remaining_events=remaining,
                reduction_pct=round(reduction, 1),
                prevented_event_ids=prevented_ids[:50],
                prevented_agents=sorted(prevented_agents),
                timeline_impact=timeline_impact,
            )
            outputs.append(result.to_dict())

        return outputs


def analyze_counterfactual(
    results: list[dict[str, Any]],
    evidence_dir: str | Path,
    scenario_file: str | Path | None = None,
) -> list[dict[str, Any]]:
    scenarios = _load_scenarios(scenario_file)
    analyzer = CounterfactualAnalyzer()
    return analyzer.analyze(results, evidence_dir, scenarios=scenarios)


def format_counterfactual_text(results: list[dict[str, Any]]) -> str:
    if not results:
        return "No scenarios to evaluate.\n"

    lines: list[str] = []
    lines.append(f"Counterfactual Analysis ({len(results)} scenarios)\n")

    for r in results:
        impact_label = r["timeline_impact"].upper()
        lines.append(f"  Scenario: {r['scenario']}")
        lines.append(f"    {r['description']}")
        lines.append(f"    Timeline impact: {impact_label}")
        lines.append(
            f"    Events prevented: {r['prevented_events']}/{r['total_events']} "
            f"({r['reduction_pct']:.1f}% reduction)"
        )
        lines.append(f"    Remaining events: {r['remaining_events']}")
        if r["prevented_agents"]:
            lines.append(f"    Agents affected: {', '.join(r['prevented_agents'][:5])}")
        if r["prevented_event_ids"]:
            shown = r["prevented_event_ids"][:5]
            lines.append(f"    Sample prevented IDs: {', '.join(shown)}")
            if len(r["prevented_event_ids"]) > 5:
                lines.append(f"      ... and {len(r['prevented_event_ids']) - 5} more")
        lines.append("")

    total_events = results[0]["total_events"] if results else 0
    best = max(results, key=lambda r: r["reduction_pct"]) if results else None
    if best and best["reduction_pct"] > 0:
        lines.append(
            f"Most effective mitigation: {best['scenario']} "
            f"({best['reduction_pct']:.1f}% event reduction)\n"
        )
    else:
        lines.append("No scenario produced measurable event reduction.\n")

    return "\n".join(lines)
