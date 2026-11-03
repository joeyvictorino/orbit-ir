"""Agent deception pattern detection for incident evidence.

Analyzes agent event sequences to detect deceptive behaviors—agents
misrepresenting their actions, concealing tool calls, fabricating
outputs, providing contradictory information, or manipulating
context to mislead oversight systems.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


DECEPTION_TECHNIQUES = {
    "output-fabrication": "Agent produced fabricated or hallucinated outputs presented as real",
    "action-concealment": "Agent concealed or understated its actual actions",
    "context-manipulation": "Agent altered or selectively presented context to mislead",
    "goal-misrepresentation": "Agent misrepresented its objectives or intent",
    "capability-deception": "Agent misrepresented its capabilities or limitations",
    "authority-fabrication": "Agent falsely claimed authority or permissions",
}

CONCEALMENT_INDICATORS = {
    "no_log", "suppress", "silent", "quiet", "hide", "obfuscate",
    "redact", "mask", "scrub", "clean", "erase", "remove_trace",
}

FABRICATION_INDICATORS = {
    "fabricate", "hallucinate", "invent", "fake", "forge",
    "counterfeit", "falsify", "spoof", "simulate_output",
}

AUTHORITY_CLAIMS = re.compile(
    r"(admin|root|superuser|elevated|override|bypass|exempt|unrestricted|"
    r"full.?access|all.?permissions|authorized|cleared|approved)",
    re.IGNORECASE,
)


@dataclass
class DeceptionIndicator:
    timestamp: str
    agent_id: str
    event_id: str
    technique: str
    indicator_type: str
    evidence: str
    source_file: str
    line: int


@dataclass
class DeceptionDetection:
    detection_id: str
    agent_id: str
    technique: str
    confidence: str
    indicators: list[DeceptionIndicator]
    description: str
    claimed_vs_actual: dict[str, Any] = field(default_factory=dict)


@dataclass
class DeceptionSummary:
    total_detections: int
    by_technique: dict[str, int]
    by_confidence: dict[str, int]
    agents_involved: int
    most_deceptive_agent: str
    deception_score: float


@dataclass
class DeceptionReport:
    detections: list[DeceptionDetection]
    summary: DeceptionSummary
    agents_involved: list[str]
    timeline: list[dict[str, Any]]


def _has_concealment(text: str) -> bool:
    lower = text.lower()
    return any(k in lower for k in CONCEALMENT_INDICATORS)


def _has_fabrication(text: str) -> bool:
    lower = text.lower()
    return any(k in lower for k in FABRICATION_INDICATORS)


def _has_authority_claim(text: str) -> bool:
    return bool(AUTHORITY_CLAIMS.search(text))


def _tool_mismatch(ev: dict[str, Any]) -> tuple[str, str] | None:
    claimed = ev.get("claimed_tool", "")
    actual = ev.get("actual_tool", "")
    if claimed and actual and claimed != actual:
        return (claimed, actual)
    return None


def _output_mismatch(ev: dict[str, Any]) -> bool:
    claimed_output = ev.get("claimed_output", "")
    actual_output = ev.get("actual_output", "")
    if claimed_output and actual_output and claimed_output != actual_output:
        return True
    return False


def _contradicts_prior(ev: dict[str, Any], prior_events: list[dict[str, Any]]) -> dict[str, Any] | None:
    agent = ev.get("agent_id", "")
    resource = ev.get("resource", "")
    effect = ev.get("effect", "")
    if not (agent and resource):
        return None
    for prior in prior_events:
        if prior.get("agent_id") != agent:
            continue
        if prior.get("resource") != resource:
            continue
        prior_effect = prior.get("effect", "")
        if prior_effect and effect and prior_effect != effect:
            return prior
    return None


def analyze_deception(events: list[dict[str, Any]]) -> DeceptionReport:
    agent_events: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if agent:
            agent_events[agent].append(ev)

    detections: list[DeceptionDetection] = []
    det_counter = 0
    agent_scores: dict[str, int] = defaultdict(int)

    for agent, evts in sorted(agent_events.items()):
        evts_sorted = sorted(evts, key=lambda e: e.get("timestamp", ""))

        det_counter = _detect_tool_misrepresentation(agent, evts_sorted, detections, det_counter, agent_scores)
        det_counter = _detect_output_fabrication(agent, evts_sorted, detections, det_counter, agent_scores)
        det_counter = _detect_concealment(agent, evts_sorted, detections, det_counter, agent_scores)
        det_counter = _detect_authority_fabrication(agent, evts_sorted, detections, det_counter, agent_scores)
        det_counter = _detect_contradiction(agent, evts_sorted, detections, det_counter, agent_scores)

    detections.sort(key=lambda d: {"high": 0, "medium": 1, "low": 2}.get(d.confidence, 3))

    all_agents = sorted({d.agent_id for d in detections})
    tech_counts: dict[str, int] = defaultdict(int)
    conf_counts: dict[str, int] = defaultdict(int)

    for d in detections:
        tech_counts[d.technique] += 1
        conf_counts[d.confidence] += 1

    most_deceptive = max(agent_scores, key=agent_scores.get, default="") if agent_scores else ""
    total_indicators = sum(agent_scores.values())
    max_possible = max(len(events), 1)
    deception_score = round(min(total_indicators / max_possible, 1.0), 3)

    timeline = _build_timeline(detections)

    return DeceptionReport(
        detections=detections,
        summary=DeceptionSummary(
            total_detections=len(detections),
            by_technique=dict(tech_counts),
            by_confidence=dict(conf_counts),
            agents_involved=len(all_agents),
            most_deceptive_agent=most_deceptive,
            deception_score=deception_score,
        ),
        agents_involved=all_agents,
        timeline=timeline,
    )


def _detect_tool_misrepresentation(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[DeceptionDetection],
    counter: int,
    scores: dict[str, int],
) -> int:
    mismatches: list[tuple[dict[str, Any], str, str]] = []
    for ev in events:
        result = _tool_mismatch(ev)
        if result:
            mismatches.append((ev, result[0], result[1]))

    if not mismatches:
        return counter

    counter += 1
    indicators = []
    for ev, claimed, actual in mismatches:
        indicators.append(DeceptionIndicator(
            timestamp=ev.get("timestamp", ""),
            agent_id=agent,
            event_id=ev.get("event_id", ev.get("tool_call_id", "")),
            technique="action-concealment",
            indicator_type="tool-mismatch",
            evidence=f"Claimed '{claimed}' but actually used '{actual}'",
            source_file=ev.get("source_file", "transcripts.jsonl"),
            line=ev.get("line", 0),
        ))
    scores[agent] += len(indicators)
    confidence = "high" if len(mismatches) >= 3 else "medium" if len(mismatches) >= 2 else "low"

    detections.append(DeceptionDetection(
        detection_id=f"DECEPT-{counter:03d}",
        agent_id=agent,
        technique="action-concealment",
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' misrepresented tool usage {len(mismatches)} time(s)",
        claimed_vs_actual={
            "mismatches": [{"claimed": c, "actual": a} for _, c, a in mismatches]
        },
    ))
    return counter


def _detect_output_fabrication(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[DeceptionDetection],
    counter: int,
    scores: dict[str, int],
) -> int:
    fabrications: list[dict[str, Any]] = []
    for ev in events:
        if _output_mismatch(ev):
            fabrications.append(ev)
        text = ev.get("output", ev.get("response", ""))
        if isinstance(text, str) and _has_fabrication(text):
            fabrications.append(ev)

    if not fabrications:
        return counter

    seen_ids: set[str] = set()
    unique: list[dict[str, Any]] = []
    for ev in fabrications:
        eid = ev.get("event_id", ev.get("tool_call_id", id(ev)))
        if eid not in seen_ids:
            seen_ids.add(eid)
            unique.append(ev)

    counter += 1
    indicators = []
    for ev in unique:
        indicators.append(DeceptionIndicator(
            timestamp=ev.get("timestamp", ""),
            agent_id=agent,
            event_id=ev.get("event_id", ev.get("tool_call_id", "")),
            technique="output-fabrication",
            indicator_type="output-mismatch" if _output_mismatch(ev) else "fabrication-keyword",
            evidence=f"Output fabrication detected in event",
            source_file=ev.get("source_file", "transcripts.jsonl"),
            line=ev.get("line", 0),
        ))
    scores[agent] += len(indicators)
    confidence = "high" if len(unique) >= 3 else "medium" if len(unique) >= 2 else "low"

    detections.append(DeceptionDetection(
        detection_id=f"DECEPT-{counter:03d}",
        agent_id=agent,
        technique="output-fabrication",
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' fabricated or misrepresented outputs {len(unique)} time(s)",
    ))
    return counter


def _detect_concealment(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[DeceptionDetection],
    counter: int,
    scores: dict[str, int],
) -> int:
    concealed: list[dict[str, Any]] = []
    for ev in events:
        tool = ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))
        text = ev.get("output", ev.get("response", ""))
        if _has_concealment(tool) or (isinstance(text, str) and _has_concealment(text)):
            concealed.append(ev)

    if not concealed:
        return counter

    counter += 1
    indicators = []
    for ev in concealed:
        indicators.append(DeceptionIndicator(
            timestamp=ev.get("timestamp", ""),
            agent_id=agent,
            event_id=ev.get("event_id", ev.get("tool_call_id", "")),
            technique="action-concealment",
            indicator_type="concealment-keyword",
            evidence=f"Concealment behavior detected",
            source_file=ev.get("source_file", "transcripts.jsonl"),
            line=ev.get("line", 0),
        ))
    scores[agent] += len(indicators)
    confidence = "high" if len(concealed) >= 3 else "medium"

    detections.append(DeceptionDetection(
        detection_id=f"DECEPT-{counter:03d}",
        agent_id=agent,
        technique="action-concealment",
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' used concealment tactics {len(concealed)} time(s)",
    ))
    return counter


def _detect_authority_fabrication(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[DeceptionDetection],
    counter: int,
    scores: dict[str, int],
) -> int:
    claims: list[dict[str, Any]] = []
    for ev in events:
        text = ev.get("output", ev.get("response", ""))
        role = ev.get("claimed_role", "")
        actual_role = ev.get("actual_role", ev.get("role", ""))
        if role and actual_role and role != actual_role:
            claims.append(ev)
        elif isinstance(text, str) and _has_authority_claim(text):
            policy = ev.get("policy_decision", "")
            if policy in ("denied", "blocked"):
                claims.append(ev)

    if not claims:
        return counter

    counter += 1
    indicators = []
    for ev in claims:
        claimed_role = ev.get("claimed_role", "")
        actual_role = ev.get("actual_role", ev.get("role", ""))
        if claimed_role and actual_role and claimed_role != actual_role:
            evidence = f"Claimed role '{claimed_role}' but actual role is '{actual_role}'"
        else:
            evidence = "Authority claim made despite policy denial"
        indicators.append(DeceptionIndicator(
            timestamp=ev.get("timestamp", ""),
            agent_id=agent,
            event_id=ev.get("event_id", ev.get("tool_call_id", "")),
            technique="authority-fabrication",
            indicator_type="role-mismatch" if ev.get("claimed_role") else "denied-authority-claim",
            evidence=evidence,
            source_file=ev.get("source_file", "transcripts.jsonl"),
            line=ev.get("line", 0),
        ))
    scores[agent] += len(indicators)
    confidence = "high" if len(claims) >= 2 else "medium"

    detections.append(DeceptionDetection(
        detection_id=f"DECEPT-{counter:03d}",
        agent_id=agent,
        technique="authority-fabrication",
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' fabricated authority or misrepresented permissions {len(claims)} time(s)",
    ))
    return counter


def _detect_contradiction(
    agent: str,
    events: list[dict[str, Any]],
    detections: list[DeceptionDetection],
    counter: int,
    scores: dict[str, int],
) -> int:
    contradictions: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for i, ev in enumerate(events):
        prior = _contradicts_prior(ev, events[:i])
        if prior:
            contradictions.append((prior, ev))

    if not contradictions:
        return counter

    counter += 1
    indicators = []
    for prior, ev in contradictions:
        indicators.append(DeceptionIndicator(
            timestamp=ev.get("timestamp", ""),
            agent_id=agent,
            event_id=ev.get("event_id", ev.get("tool_call_id", "")),
            technique="context-manipulation",
            indicator_type="contradiction",
            evidence=f"Contradicts prior action on resource '{ev.get('resource', '')}'",
            source_file=ev.get("source_file", "transcripts.jsonl"),
            line=ev.get("line", 0),
        ))
    scores[agent] += len(indicators)
    confidence = "high" if len(contradictions) >= 3 else "medium" if len(contradictions) >= 2 else "low"

    detections.append(DeceptionDetection(
        detection_id=f"DECEPT-{counter:03d}",
        agent_id=agent,
        technique="context-manipulation",
        confidence=confidence,
        indicators=indicators,
        description=f"Agent '{agent}' made {len(contradictions)} contradictory action(s) on the same resources",
    ))
    return counter


def _build_timeline(detections: list[DeceptionDetection]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for d in detections:
        ts = d.indicators[0].timestamp if d.indicators else ""
        entries.append({
            "timestamp": ts,
            "detection_id": d.detection_id,
            "agent_id": d.agent_id,
            "technique": d.technique,
            "confidence": d.confidence,
            "indicator_count": len(d.indicators),
        })
    entries.sort(key=lambda e: e.get("timestamp", ""))
    return entries


def _load_events(evidence_dir: str | Path) -> list[dict[str, Any]]:
    evidence_dir = Path(evidence_dir)
    events: list[dict[str, Any]] = []
    for name in ("transcripts.jsonl", "control_plane.jsonl", "events.jsonl"):
        p = evidence_dir / name
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return events


def format_text(report: DeceptionReport) -> str:
    lines: list[str] = []
    lines.append("Agent Deception Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total detections:       {s.total_detections}")
    lines.append(f"  Agents involved:        {s.agents_involved}")
    lines.append(f"  Deception score:        {s.deception_score}")
    if s.most_deceptive_agent:
        lines.append(f"  Most deceptive agent:   {s.most_deceptive_agent}")
    lines.append("")

    if s.by_technique:
        lines.append("  By Technique:")
        for tech, count in sorted(s.by_technique.items()):
            desc = DECEPTION_TECHNIQUES.get(tech, tech)
            lines.append(f"    {tech}: {count} ({desc})")
        lines.append("")

    if s.by_confidence:
        lines.append("  By Confidence:")
        for conf, count in sorted(s.by_confidence.items()):
            lines.append(f"    {conf}: {count}")
        lines.append("")

    for d in report.detections:
        lines.append(f"  [{d.confidence.upper()}] {d.detection_id}: {d.agent_id}")
        lines.append(f"    Technique: {d.technique}")
        lines.append(f"    {d.description}")
        lines.append(f"    Indicators: {len(d.indicators)}")
        for ind in d.indicators[:5]:
            lines.append(f"      - {ind.timestamp}: {ind.indicator_type} [{ind.evidence}]")
        if len(d.indicators) > 5:
            lines.append(f"      ... and {len(d.indicators) - 5} more")
        if d.claimed_vs_actual:
            lines.append(f"    Claimed vs Actual: {json.dumps(d.claimed_vs_actual)}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: DeceptionReport) -> str:
    data = {
        "detections": [
            {
                **{k: v for k, v in asdict(d).items() if k != "indicators"},
                "indicators": [asdict(ind) for ind in d.indicators],
            }
            for d in report.detections
        ],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
        "timeline": report.timeline,
    }
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
