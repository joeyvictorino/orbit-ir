"""Causal chain builder linking events by shared entities."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PATH_RE = re.compile(r"(?:/[\w._-]+){2,}")


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
                        pass
        else:
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    events.extend(data)
                elif isinstance(data, dict):
                    events.append(data)
            except json.JSONDecodeError:
                pass
    return events


def _extract_entities(event: dict[str, Any]) -> set[str]:
    entities: set[str] = set()
    for key in ("agent_id", "src_agent", "dst_agent", "sender", "receiver", "agent"):
        val = event.get(key)
        if isinstance(val, str) and val:
            entities.add(f"agent:{val}")
    for key in ("resource", "target", "tool_name", "tool", "action"):
        val = event.get(key)
        if isinstance(val, str) and val:
            entities.add(f"resource:{val}")
    for key in ("ip", "src_ip", "dst_ip", "address"):
        val = event.get(key)
        if isinstance(val, str) and val:
            entities.add(f"ip:{val}")
    text = json.dumps(event, default=str)
    for ip in _IPV4_RE.findall(text):
        if not ip.startswith("0.") and ip != "127.0.0.1":
            entities.add(f"ip:{ip}")
    for fp in _PATH_RE.findall(text):
        entities.add(f"path:{fp}")
    return entities


def _parse_ts(event: dict[str, Any]) -> float:
    ts = event.get("timestamp") or event.get("ts") or ""
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str) and ts:
        import datetime as _dt
        try:
            dt = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.timestamp()
        except (ValueError, TypeError):
            pass
    return 0.0


def _severity_score(event: dict[str, Any]) -> float:
    sev = (event.get("severity") or event.get("risk") or "").lower()
    return {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}.get(sev, 0.1)


class EvidenceChainBuilder:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.chains: list[dict[str, Any]] = []

    def load_events(self, path: Path | str) -> None:
        self.events = _load_events(Path(path))
        self.events.sort(key=_parse_ts)

    def build_chains(self, min_chain_length: int = 2, max_chains: int = 20) -> None:
        event_entities: list[tuple[dict[str, Any], set[str]]] = []
        for ev in self.events:
            ents = _extract_entities(ev)
            if ents:
                event_entities.append((ev, ents))

        n = len(event_entities)
        visited = [False] * n
        raw_chains: list[list[int]] = []

        entity_index: dict[str, list[int]] = defaultdict(list)
        for idx, (_, ents) in enumerate(event_entities):
            for e in ents:
                entity_index[e].append(idx)

        for start in range(n):
            if visited[start]:
                continue
            chain_indices: list[int] = []
            queue = [start]
            seen = {start}
            while queue:
                cur = queue.pop(0)
                chain_indices.append(cur)
                visited[cur] = True
                _, cur_ents = event_entities[cur]
                for ent in cur_ents:
                    for neighbor in entity_index[ent]:
                        if neighbor not in seen:
                            seen.add(neighbor)
                            queue.append(neighbor)
            chain_indices.sort(key=lambda i: _parse_ts(event_entities[i][0]))
            if len(chain_indices) >= min_chain_length:
                raw_chains.append(chain_indices)

        raw_chains.sort(key=lambda c: -len(c))
        raw_chains = raw_chains[:max_chains]

        self.chains = []
        for cid, indices in enumerate(raw_chains, 1):
            chain_events = [event_entities[i][0] for i in indices]
            all_entities: set[str] = set()
            for i in indices:
                all_entities |= event_entities[i][1]

            timestamps = [_parse_ts(ev) for ev in chain_events]
            valid_ts = [t for t in timestamps if t > 0]
            duration = (max(valid_ts) - min(valid_ts)) if len(valid_ts) >= 2 else 0.0

            sev_sum = sum(_severity_score(ev) for ev in chain_events)
            entity_diversity = len(all_entities)
            risk = round(min(1.0, (sev_sum / max(len(chain_events), 1)) * 0.5
                              + min(len(chain_events) / 20, 0.3)
                              + min(entity_diversity / 30, 0.2)), 3)

            self.chains.append({
                "chain_id": cid,
                "events": [_event_summary(ev) for ev in chain_events],
                "shared_entities": sorted(all_entities),
                "event_count": len(chain_events),
                "duration_seconds": round(duration, 1),
                "risk_score": risk,
            })

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_events": len(self.events),
            "total_chains": len(self.chains),
            "chains": self.chains,
        }


def _event_summary(ev: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent_id": ev.get("agent_id") or ev.get("src_agent", ""),
        "timestamp": ev.get("timestamp", ""),
        "type": ev.get("type") or ev.get("event_type") or ev.get("detection_type", ""),
        "summary": ev.get("content", ev.get("action", ""))[:120] if ev.get("content") or ev.get("action") else "",
    }


def build_evidence_chains(
    path: Path | str,
    min_chain_length: int = 2,
    max_chains: int = 20,
) -> EvidenceChainBuilder:
    builder = EvidenceChainBuilder()
    builder.load_events(Path(path))
    builder.build_chains(min_chain_length=min_chain_length, max_chains=max_chains)
    return builder


def format_evidence_chain_text(data: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"Evidence Chains ({data['total_chains']} chains from {data['total_events']} events)")
    lines.append("=" * 60)
    lines.append("")

    for chain in data["chains"]:
        lines.append(f"Chain #{chain['chain_id']}  "
                     f"({chain['event_count']} events, "
                     f"{chain['duration_seconds']}s, "
                     f"risk={chain['risk_score']:.3f})")
        lines.append(f"  Shared entities: {', '.join(chain['shared_entities'][:10])}")
        for ev in chain["events"][:10]:
            ts = ev.get("timestamp", "")[:19]
            agent = ev.get("agent_id", "?")
            etype = ev.get("type", "")
            lines.append(f"    {ts}  {agent:<20s}  {etype}")
        if chain["event_count"] > 10:
            lines.append(f"    ... and {chain['event_count'] - 10} more events")
        lines.append("")

    return "\n".join(lines) + "\n"
