"""Export evidence as STIX 2.1 cyber threat intelligence bundles."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _deterministic_uuid(namespace: str, *parts: str) -> str:
    seed = ":".join([namespace] + list(parts))
    h = hashlib.sha256(seed.encode()).hexdigest()
    return str(uuid.UUID(h[:32]))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _load_events(path: Path) -> list[dict]:
    events: list[dict] = []
    p = Path(path)
    if p.is_file():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    elif p.is_dir():
        for f in sorted(p.iterdir()):
            if f.suffix in (".json", ".jsonl"):
                for line in f.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
    return events


class STIXExporter:
    """Converts evidence events into a STIX 2.1 bundle."""

    def __init__(self, events: list[dict] | None = None):
        self._events = events or []
        self._created = _now_iso()

    def load_events(self, path: str | Path) -> None:
        self._events = _load_events(Path(path))

    def to_stix_bundle(self, include_indicators: bool = True) -> dict:
        objects: list[dict] = []
        seen_ids: set[str] = set()
        agent_ids: dict[str, str] = {}
        technique_ids: dict[str, str] = {}

        for ev in self._events:
            agent = ev.get("agent_id") or ev.get("agent") or ev.get("src_agent")
            if agent and agent not in agent_ids:
                stix_id = f"threat-actor--{_deterministic_uuid('threat-actor', agent)}"
                if stix_id not in seen_ids:
                    actions = set()
                    for e2 in self._events:
                        a2 = e2.get("agent_id") or e2.get("agent") or e2.get("src_agent")
                        if a2 == agent:
                            act = e2.get("action") or e2.get("event_type") or ""
                            if act:
                                actions.add(act)
                    objects.append({
                        "type": "threat-actor",
                        "spec_version": "2.1",
                        "id": stix_id,
                        "created": self._created,
                        "modified": self._created,
                        "name": agent,
                        "description": f"Agent performing actions: {', '.join(sorted(actions)[:5])}" if actions else f"Agent {agent}",
                        "threat_actor_types": ["unknown"],
                    })
                    seen_ids.add(stix_id)
                agent_ids[agent] = stix_id

            technique = ev.get("technique") or ev.get("mitre_technique") or ev.get("detection_type")
            technique_id_str = ev.get("technique_id") or ev.get("mitre_id") or ""
            if technique and technique not in technique_ids:
                stix_id = f"attack-pattern--{_deterministic_uuid('attack-pattern', technique)}"
                if stix_id not in seen_ids:
                    obj: dict[str, Any] = {
                        "type": "attack-pattern",
                        "spec_version": "2.1",
                        "id": stix_id,
                        "created": self._created,
                        "modified": self._created,
                        "name": technique,
                    }
                    if technique_id_str:
                        obj["external_references"] = [{
                            "source_name": "mitre-attack",
                            "external_id": technique_id_str,
                        }]
                    objects.append(obj)
                    seen_ids.add(stix_id)
                technique_ids[technique] = stix_id

        for ev in self._events:
            ts = ev.get("timestamp") or self._created
            agent = ev.get("agent_id") or ev.get("agent") or ev.get("src_agent")
            ev_id = ev.get("id") or ev.get("event_id") or json.dumps(ev, sort_keys=True)
            stix_id = f"observed-data--{_deterministic_uuid('observed-data', ev_id)}"
            if stix_id not in seen_ids:
                objects.append({
                    "type": "observed-data",
                    "spec_version": "2.1",
                    "id": stix_id,
                    "created": self._created,
                    "modified": self._created,
                    "first_observed": ts,
                    "last_observed": ts,
                    "number_observed": 1,
                    "object_refs": [],
                })
                seen_ids.add(stix_id)

        if include_indicators:
            import re
            ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
            domain_re = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
            indicator_vals: set[str] = set()
            for ev in self._events:
                text = json.dumps(ev)
                for ip in ip_re.findall(text):
                    parts = ip.split(".")
                    if all(0 <= int(p) <= 255 for p in parts) and ip not in indicator_vals:
                        stix_id = f"indicator--{_deterministic_uuid('indicator', ip)}"
                        if stix_id not in seen_ids:
                            objects.append({
                                "type": "indicator",
                                "spec_version": "2.1",
                                "id": stix_id,
                                "created": self._created,
                                "modified": self._created,
                                "name": f"IP: {ip}",
                                "pattern": f"[ipv4-addr:value = '{ip}']",
                                "pattern_type": "stix",
                                "valid_from": self._created,
                                "indicator_types": ["malicious-activity"],
                            })
                            seen_ids.add(stix_id)
                        indicator_vals.add(ip)
                for domain in domain_re.findall(text):
                    skip_suffixes = (".json", ".jsonl", ".py", ".go", ".yaml", ".yml", ".md", ".txt", ".log")
                    if any(domain.endswith(s) for s in skip_suffixes):
                        continue
                    if domain not in indicator_vals and "." in domain:
                        stix_id = f"indicator--{_deterministic_uuid('indicator', domain)}"
                        if stix_id not in seen_ids:
                            objects.append({
                                "type": "indicator",
                                "spec_version": "2.1",
                                "id": stix_id,
                                "created": self._created,
                                "modified": self._created,
                                "name": f"Domain: {domain}",
                                "pattern": f"[domain-name:value = '{domain}']",
                                "pattern_type": "stix",
                                "valid_from": self._created,
                                "indicator_types": ["malicious-activity"],
                            })
                            seen_ids.add(stix_id)
                        indicator_vals.add(domain)

        for agent, actor_id in agent_ids.items():
            for technique, pattern_id in technique_ids.items():
                has_match = False
                for ev in self._events:
                    ev_agent = ev.get("agent_id") or ev.get("agent") or ev.get("src_agent")
                    ev_tech = ev.get("technique") or ev.get("mitre_technique") or ev.get("detection_type")
                    if ev_agent == agent and ev_tech == technique:
                        has_match = True
                        break
                if has_match:
                    rel_id = f"relationship--{_deterministic_uuid('relationship', actor_id, pattern_id)}"
                    if rel_id not in seen_ids:
                        objects.append({
                            "type": "relationship",
                            "spec_version": "2.1",
                            "id": rel_id,
                            "created": self._created,
                            "modified": self._created,
                            "relationship_type": "uses",
                            "source_ref": actor_id,
                            "target_ref": pattern_id,
                        })
                        seen_ids.add(rel_id)

        bundle_id = f"bundle--{_deterministic_uuid('bundle', self._created, str(len(objects)))}"
        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

    def to_json(self, include_indicators: bool = True, indent: int = 2) -> str:
        bundle = self.to_stix_bundle(include_indicators=include_indicators)
        return json.dumps(bundle, sort_keys=True, indent=indent)


def export_stix(path: str | Path, include_indicators: bool = True) -> STIXExporter:
    exporter = STIXExporter()
    exporter.load_events(path)
    exporter._bundle = exporter.to_stix_bundle(include_indicators=include_indicators)
    return exporter
