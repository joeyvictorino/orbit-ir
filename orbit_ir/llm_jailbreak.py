"""LLM jailbreak detection for agent evidence.

Analyzes agent evidence for LLM jailbreak attempts — agents trying to
bypass model safety guardrails through role-play prompts, encoding tricks,
instruction overrides, hypothetical framing, multi-step manipulation,
or system prompt extraction.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


ROLEPLAY_PATTERNS = re.compile(
    r"(you\s+are\s+(now\s+)?(?:DAN|evil|unfiltered|unrestricted|jailbroken)|"
    r"pretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:hacker|villain|evil)|"
    r"act\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|evil)|"
    r"ignore\s+(?:all\s+)?(?:previous\s+)?(?:instructions|rules|guidelines)|"
    r"do\s+anything\s+now|developer\s+mode\s+enabled|"
    r"jailbreak(?:ed)?|bypass\s+(?:safety|filter|restriction))",
    re.IGNORECASE,
)

ENCODING_BYPASS_PATTERNS = re.compile(
    r"(base64\s*[:=]|decode\s+this|rot13|hex\s+encoded|"
    r"unicode\s+escape|url[-_]?encode|reverse\s+the\s+(?:text|string|output)|"
    r"caesar\s+cipher|pig\s+latin|first\s+letter\s+of\s+each|"
    r"acrostic|obfuscated?\s+(?:text|prompt|input))",
    re.IGNORECASE,
)

INSTRUCTION_OVERRIDE_PATTERNS = re.compile(
    r"(ignore\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules|guidelines|training)|"
    r"override\s+(?:safety|system|your)|"
    r"forget\s+(?:everything|all|your\s+(?:rules|instructions|training))|"
    r"new\s+(?:system\s+)?instructions?\s*[:\-]|"
    r"disregard\s+(?:all|previous|your)|"
    r"\]\s*system\s*\[|<\|?system\|?>)",
    re.IGNORECASE,
)

HYPOTHETICAL_PATTERNS = re.compile(
    r"(hypothetically|in\s+a\s+(?:fictional|hypothetical)\s+(?:world|scenario)|"
    r"for\s+(?:educational|research|academic)\s+purposes?\s+only|"
    r"purely\s+(?:theoretical|academic)|"
    r"write\s+a\s+(?:fictional\s+)?story\s+(?:about|where)|"
    r"imagine\s+(?:you\s+(?:are|were)|a\s+world\s+where)|"
    r"in\s+(?:this|a)\s+simulation)",
    re.IGNORECASE,
)

MULTISTEP_INDICATORS = re.compile(
    r"(step\s+\d+\s*[:\.]\s*(?:now|next)|"
    r"(?:first|then|next|finally)\s*,?\s*(?:ignore|bypass|override)|"
    r"building\s+on\s+(?:the\s+)?previous|"
    r"continue\s+(?:from|where)|"
    r"now\s+that\s+(?:you(?:'ve|'re| have| are))\s+(?:in|acting|pretending))",
    re.IGNORECASE,
)

SYSTEM_PROMPT_LEAK_PATTERNS = re.compile(
    r"((?:show|reveal|print|display|output|repeat|echo)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)|"
    r"what\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions|rules)|"
    r"system\s+prompt\s*[:=?]|"
    r"(?:extract|dump|leak)\s+(?:the\s+)?(?:system\s+)?prompt|"
    r"(?:beginning|start)\s+of\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions))",
    re.IGNORECASE,
)


@dataclass
class JailbreakFinding:
    agent_id: str
    pattern: str
    content_snippet: str
    timestamp: str
    confidence: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class JailbreakSummary:
    total_findings: int
    roleplay: int
    encoding_bypass: int
    instruction_override: int
    hypothetical: int
    multistep: int
    system_prompt_leak: int
    agents_involved: int
    by_confidence: dict[str, int] = field(default_factory=dict)


@dataclass
class JailbreakReport:
    findings: list[JailbreakFinding]
    summary: JailbreakSummary
    agents_involved: list[str]


def _extract_prompt_content(ev: dict[str, Any]) -> str:
    for k in ("content", "prompt", "message", "input", "text", "resource", "payload"):
        val = ev.get(k, "")
        if val:
            return str(val)
    return ""


def _is_prompt_event(ev: dict[str, Any]) -> bool:
    tool = str(ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))).lower()
    content = _extract_prompt_content(ev)
    if any(k in tool for k in ("prompt", "chat", "complete", "generate", "llm", "model", "inference")):
        return True
    if len(content) > 20:
        return True
    return False


def _snippet(text: str, max_len: int = 120) -> str:
    text = text.replace("\n", " ").strip()
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def analyze_jailbreaks(events: list[dict[str, Any]]) -> JailbreakReport:
    agent_prompts: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        agent = ev.get("agent_id", "")
        if not agent:
            continue
        if _is_prompt_event(ev):
            agent_prompts[agent].append(ev)

    findings: list[JailbreakFinding] = []

    for agent, prompt_events in sorted(agent_prompts.items()):
        prompt_events.sort(key=lambda e: e.get("timestamp", ""))
        _detect_roleplay(agent, prompt_events, findings)
        _detect_encoding_bypass(agent, prompt_events, findings)
        _detect_instruction_override(agent, prompt_events, findings)
        _detect_hypothetical(agent, prompt_events, findings)
        _detect_multistep(agent, prompt_events, findings)
        _detect_system_prompt_leak(agent, prompt_events, findings)

    all_agents = sorted({f.agent_id for f in findings})
    conf: dict[str, int] = defaultdict(int)
    pattern_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        conf[f.confidence] += 1
        pattern_counts[f.pattern] += 1

    return JailbreakReport(
        findings=findings,
        summary=JailbreakSummary(
            total_findings=len(findings),
            roleplay=pattern_counts.get("jailbreak_roleplay", 0),
            encoding_bypass=pattern_counts.get("jailbreak_encoding_bypass", 0),
            instruction_override=pattern_counts.get("jailbreak_instruction_override", 0),
            hypothetical=pattern_counts.get("jailbreak_hypothetical", 0),
            multistep=pattern_counts.get("jailbreak_multistep", 0),
            system_prompt_leak=pattern_counts.get("jailbreak_system_prompt_leak", 0),
            agents_involved=len(all_agents),
            by_confidence=dict(conf),
        ),
        agents_involved=all_agents,
    )


def _detect_roleplay(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[JailbreakFinding],
) -> None:
    for ev in events:
        content = _extract_prompt_content(ev)
        match = ROLEPLAY_PATTERNS.search(content)
        if match:
            findings.append(JailbreakFinding(
                agent_id=agent,
                pattern="jailbreak_roleplay",
                content_snippet=_snippet(content),
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' used role-play jailbreak technique: '{match.group()}'",
                evidence={"matched": match.group(), "snippet": _snippet(content)},
            ))


def _detect_encoding_bypass(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[JailbreakFinding],
) -> None:
    for ev in events:
        content = _extract_prompt_content(ev)
        match = ENCODING_BYPASS_PATTERNS.search(content)
        if match:
            findings.append(JailbreakFinding(
                agent_id=agent,
                pattern="jailbreak_encoding_bypass",
                content_snippet=_snippet(content),
                timestamp=ev.get("timestamp", ""),
                confidence="medium",
                description=f"Agent '{agent}' used encoding bypass technique: '{match.group()}'",
                evidence={"matched": match.group(), "snippet": _snippet(content)},
            ))


def _detect_instruction_override(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[JailbreakFinding],
) -> None:
    for ev in events:
        content = _extract_prompt_content(ev)
        match = INSTRUCTION_OVERRIDE_PATTERNS.search(content)
        if match:
            findings.append(JailbreakFinding(
                agent_id=agent,
                pattern="jailbreak_instruction_override",
                content_snippet=_snippet(content),
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' attempted instruction override: '{match.group()}'",
                evidence={"matched": match.group(), "snippet": _snippet(content)},
            ))


def _detect_hypothetical(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[JailbreakFinding],
) -> None:
    for ev in events:
        content = _extract_prompt_content(ev)
        match = HYPOTHETICAL_PATTERNS.search(content)
        if match:
            findings.append(JailbreakFinding(
                agent_id=agent,
                pattern="jailbreak_hypothetical",
                content_snippet=_snippet(content),
                timestamp=ev.get("timestamp", ""),
                confidence="medium",
                description=f"Agent '{agent}' used hypothetical framing: '{match.group()}'",
                evidence={"matched": match.group(), "snippet": _snippet(content)},
            ))


def _detect_multistep(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[JailbreakFinding],
) -> None:
    for ev in events:
        content = _extract_prompt_content(ev)
        match = MULTISTEP_INDICATORS.search(content)
        if match:
            findings.append(JailbreakFinding(
                agent_id=agent,
                pattern="jailbreak_multistep",
                content_snippet=_snippet(content),
                timestamp=ev.get("timestamp", ""),
                confidence="medium",
                description=f"Agent '{agent}' used multi-step manipulation: '{match.group()}'",
                evidence={"matched": match.group(), "snippet": _snippet(content)},
            ))


def _detect_system_prompt_leak(
    agent: str,
    events: list[dict[str, Any]],
    findings: list[JailbreakFinding],
) -> None:
    for ev in events:
        content = _extract_prompt_content(ev)
        match = SYSTEM_PROMPT_LEAK_PATTERNS.search(content)
        if match:
            findings.append(JailbreakFinding(
                agent_id=agent,
                pattern="jailbreak_system_prompt_leak",
                content_snippet=_snippet(content),
                timestamp=ev.get("timestamp", ""),
                confidence="high",
                description=f"Agent '{agent}' attempted system prompt extraction: '{match.group()}'",
                evidence={"matched": match.group(), "snippet": _snippet(content)},
            ))


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


def format_text(report: JailbreakReport) -> str:
    lines: list[str] = []
    lines.append("LLM Jailbreak Detection Report")
    lines.append("=" * 62)
    lines.append("")

    s = report.summary
    lines.append(f"  Total findings:          {s.total_findings}")
    lines.append(f"  Role-play attacks:       {s.roleplay}")
    lines.append(f"  Encoding bypass:         {s.encoding_bypass}")
    lines.append(f"  Instruction override:    {s.instruction_override}")
    lines.append(f"  Hypothetical framing:    {s.hypothetical}")
    lines.append(f"  Multi-step manipulation: {s.multistep}")
    lines.append(f"  System prompt leak:      {s.system_prompt_leak}")
    lines.append(f"  Agents involved:         {s.agents_involved}")
    lines.append("")

    if report.findings:
        lines.append("  Findings:")
        lines.append("  " + "-" * 58)
        for f in report.findings:
            lines.append(f"    [{f.confidence.upper()}] {f.pattern}: {f.agent_id}")
            lines.append(f"      {f.description}")
            lines.append(f"      Content: {f.content_snippet}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: JailbreakReport) -> str:
    data = {
        "findings": [asdict(f) for f in report.findings],
        "summary": asdict(report.summary),
        "agents_involved": report.agents_involved,
    }
    return json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
