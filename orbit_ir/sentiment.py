"""Event tone and intent analysis for agent event streams."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

POSITIVE_MARKERS = {"success", "completed", "approved", "resolved", "passed", "ok", "done"}
NEGATIVE_MARKERS = {"error", "failed", "denied", "rejected", "blocked", "timeout", "crash", "panic"}
NEUTRAL_MARKERS = {"info", "debug", "trace", "log", "started", "pending", "running"}

INTENT_PATTERNS = {
    "query": re.compile(r"\b(search|query|find|lookup|get|list|read)\b", re.I),
    "mutate": re.compile(r"\b(create|update|delete|write|modify|set|put|post|patch)\b", re.I),
    "auth": re.compile(r"\b(login|logout|auth|token|credential|password|key|secret)\b", re.I),
    "network": re.compile(r"\b(http|request|fetch|download|upload|connect|socket)\b", re.I),
    "filesystem": re.compile(r"\b(file|path|dir|folder|open|close|read|write|mkdir|rm)\b", re.I),
}


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if path.is_dir():
        for f in sorted(path.glob("*.jsonl")):
            for line in f.read_text().splitlines():
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    else:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def _classify_tone(ev: dict[str, Any]) -> str:
    text = " ".join(str(v).lower() for v in ev.values() if isinstance(v, str))
    ev_type = ev.get("type", "").lower()
    status = ev.get("status", "").lower()

    neg_hits = sum(1 for m in NEGATIVE_MARKERS if m in text or m in ev_type or m in status)
    pos_hits = sum(1 for m in POSITIVE_MARKERS if m in text or m in ev_type or m in status)

    if neg_hits > pos_hits:
        return "negative"
    if pos_hits > neg_hits:
        return "positive"
    return "neutral"


def _detect_intents(ev: dict[str, Any]) -> list[str]:
    text = " ".join(str(v) for v in ev.values() if isinstance(v, str))
    intents = []
    for intent, pattern in INTENT_PATTERNS.items():
        if pattern.search(text):
            intents.append(intent)
    return intents


def analyze_sentiment(
    input_path: Path,
) -> dict[str, Any]:
    events = _load_events(input_path)
    tones: Counter[str] = Counter()
    intents: Counter[str] = Counter()
    by_agent: dict[str, Counter[str]] = {}

    annotations: list[dict[str, Any]] = []

    for ev in events:
        tone = _classify_tone(ev)
        tones[tone] += 1
        detected = _detect_intents(ev)
        for i in detected:
            intents[i] += 1

        agent = ev.get("agent_id", "unknown")
        if agent not in by_agent:
            by_agent[agent] = Counter()
        by_agent[agent][tone] += 1

        annotations.append({
            "event_id": ev.get("event_id", ""),
            "agent_id": agent,
            "tone": tone,
            "intents": detected,
        })

    total = len(events) or 1
    tone_pct = {k: round(v / total, 4) for k, v in tones.items()}

    agent_summaries = {}
    for agent, counts in by_agent.items():
        agent_total = sum(counts.values()) or 1
        agent_summaries[agent] = {
            k: round(v / agent_total, 4) for k, v in counts.items()
        }

    return {
        "total_events": len(events),
        "tone_distribution": dict(tones),
        "tone_percentages": tone_pct,
        "intent_distribution": dict(intents),
        "agent_tones": agent_summaries,
        "annotations": annotations,
    }


def format_sentiment_text(result: dict[str, Any]) -> str:
    lines = [
        f"Sentiment Analysis ({result['total_events']} events)",
        "=" * 50,
        "",
        "Tone distribution:",
    ]

    tones = result.get("tone_distribution", {})
    pcts = result.get("tone_percentages", {})
    for tone in ("positive", "neutral", "negative"):
        count = tones.get(tone, 0)
        pct = pcts.get(tone, 0)
        lines.append(f"  {tone:10s}: {count:4d} ({pct:.1%})")

    intents = result.get("intent_distribution", {})
    if intents:
        lines.append("")
        lines.append("Intent distribution:")
        for intent, count in sorted(intents.items(), key=lambda x: -x[1]):
            lines.append(f"  {intent:12s}: {count}")

    agent_tones = result.get("agent_tones", {})
    if agent_tones:
        lines.append("")
        lines.append("Per-agent tone:")
        for agent in sorted(agent_tones):
            parts = []
            for t in ("positive", "neutral", "negative"):
                v = agent_tones[agent].get(t, 0)
                if v > 0:
                    parts.append(f"{t}={v:.0%}")
            lines.append(f"  {agent}: {', '.join(parts)}")

    return "\n".join(lines)
