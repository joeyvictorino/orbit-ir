"""Threat intelligence enrichment — match extracted IOCs against known threat feeds."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


_KNOWN_MALICIOUS_RANGES = [
    "10.255.0.0/16",
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
]

_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".loan", ".gq", ".ml",
    ".cf", ".tk", ".buzz", ".icu", ".surf",
}

_KNOWN_MALWARE_HASH_PREFIXES = {
    "deadbeef", "cafebabe", "badc0de", "0badf00d", "feedface",
}

_THREAT_CATEGORIES = {
    "malware": {"trojan", "ransomware", "worm", "backdoor", "keylogger", "rootkit"},
    "c2": {"command-and-control", "c2", "beacon", "callback", "exfil"},
    "phishing": {"phish", "credential-harvest", "social-engineering"},
    "exploit": {"cve-", "exploit", "0day", "vulnerability"},
}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


@dataclass
class ThreatMatch:
    ioc_value: str
    ioc_type: str
    threat_category: str
    confidence: float
    description: str
    source: str
    severity: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatIntelReport:
    total_events: int
    iocs_extracted: int
    matches_found: int
    matches: list[ThreatMatch]
    ioc_summary: dict[str, int]
    threat_categories: dict[str, int]
    high_confidence_count: int
    overall_threat_level: str


def _extract_iocs_from_events(events: list[dict[str, Any]]) -> dict[str, set[str]]:
    iocs: dict[str, set[str]] = {"ip": set(), "domain": set(), "hash": set()}
    for ev in events:
        text = json.dumps(ev)
        for ip in _IP_RE.findall(text):
            try:
                ipaddress.ip_address(ip)
                iocs["ip"].add(ip)
            except ValueError:
                continue
        for domain in _DOMAIN_RE.findall(text):
            if "." in domain and not domain.replace(".", "").isdigit():
                iocs["domain"].add(domain.lower())
        for h in _HASH_RE.findall(text):
            if len(h) in (32, 40, 64):
                iocs["hash"].add(h.lower())
    return iocs


def _check_ip_reputation(ip: str) -> ThreatMatch | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for cidr in _KNOWN_MALICIOUS_RANGES:
        if addr in ipaddress.ip_network(cidr):
            return ThreatMatch(
                ioc_value=ip,
                ioc_type="ip",
                threat_category="suspicious_network",
                confidence=0.6,
                description=f"IP {ip} falls within known suspicious range {cidr}",
                source="builtin_ip_ranges",
                severity="medium",
                details={"network": cidr},
            )
    if addr.is_private:
        return None
    octets = str(addr).split(".")
    if octets[0] in ("0", "255") or octets[-1] in ("0", "255"):
        return ThreatMatch(
            ioc_value=ip,
            ioc_type="ip",
            threat_category="anomalous_network",
            confidence=0.3,
            description=f"IP {ip} has unusual octet pattern",
            source="heuristic",
            severity="low",
        )
    return None


def _check_domain_reputation(domain: str) -> ThreatMatch | None:
    for tld in _SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return ThreatMatch(
                ioc_value=domain,
                ioc_type="domain",
                threat_category="suspicious_domain",
                confidence=0.5,
                description=f"Domain {domain} uses suspicious TLD {tld}",
                source="builtin_tld_list",
                severity="medium",
                details={"tld": tld},
            )
    parts = domain.split(".")
    if len(parts) > 4:
        return ThreatMatch(
            ioc_value=domain,
            ioc_type="domain",
            threat_category="dga_candidate",
            confidence=0.4,
            description=f"Domain {domain} has excessive subdomain depth ({len(parts)} levels)",
            source="heuristic",
            severity="medium",
            details={"depth": len(parts)},
        )
    label = parts[0]
    if len(label) > 20 and sum(1 for c in label if c.isdigit()) > len(label) * 0.4:
        return ThreatMatch(
            ioc_value=domain,
            ioc_type="domain",
            threat_category="dga_candidate",
            confidence=0.6,
            description=f"Domain {domain} matches DGA-like pattern (long, high digit ratio)",
            source="heuristic",
            severity="high",
            details={"label_length": len(label)},
        )
    return None


def _check_hash_reputation(h: str) -> ThreatMatch | None:
    prefix = h[:8]
    for known in _KNOWN_MALWARE_HASH_PREFIXES:
        if prefix == known:
            return ThreatMatch(
                ioc_value=h,
                ioc_type="hash",
                threat_category="known_malware",
                confidence=0.9,
                description=f"Hash {h[:16]}... matches known malware signature prefix",
                source="builtin_hash_db",
                severity="critical",
                details={"hash_length": len(h), "prefix_match": known},
            )
    return None


def _classify_event_threats(events: list[dict[str, Any]]) -> list[ThreatMatch]:
    matches = []
    for ev in events:
        text = json.dumps(ev).lower()
        for category, keywords in _THREAT_CATEGORIES.items():
            for kw in keywords:
                if kw in text:
                    matches.append(ThreatMatch(
                        ioc_value=kw,
                        ioc_type="keyword",
                        threat_category=category,
                        confidence=0.4,
                        description=f"Event contains threat keyword '{kw}' ({category})",
                        source="keyword_match",
                        severity="low" if category == "phishing" else "medium",
                        details={"keyword": kw, "event_timestamp": ev.get("timestamp", "")},
                    ))
                    break
    return matches


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


def analyze(
    evidence_dir: str | Path,
    custom_feeds: dict[str, list[str]] | None = None,
) -> ThreatIntelReport:
    events = _load_events(Path(evidence_dir))

    if not events:
        return ThreatIntelReport(
            total_events=0,
            iocs_extracted=0,
            matches_found=0,
            matches=[],
            ioc_summary={},
            threat_categories={},
            high_confidence_count=0,
            overall_threat_level="none",
        )

    iocs = _extract_iocs_from_events(events)
    all_matches: list[ThreatMatch] = []

    for ip in iocs["ip"]:
        m = _check_ip_reputation(ip)
        if m:
            all_matches.append(m)

    for domain in iocs["domain"]:
        m = _check_domain_reputation(domain)
        if m:
            all_matches.append(m)

    for h in iocs["hash"]:
        m = _check_hash_reputation(h)
        if m:
            all_matches.append(m)

    if custom_feeds:
        for feed_name, indicators in custom_feeds.items():
            indicator_set = set(i.lower() for i in indicators)
            for ioc_type, values in iocs.items():
                for v in values:
                    if v.lower() in indicator_set:
                        all_matches.append(ThreatMatch(
                            ioc_value=v,
                            ioc_type=ioc_type,
                            threat_category="custom_feed_match",
                            confidence=0.8,
                            description=f"IOC {v} found in custom feed '{feed_name}'",
                            source=feed_name,
                            severity="high",
                        ))

    all_matches.extend(_classify_event_threats(events))

    seen: set[tuple[str, str]] = set()
    deduped: list[ThreatMatch] = []
    for m in all_matches:
        key = (m.ioc_value, m.threat_category)
        if key not in seen:
            seen.add(key)
            deduped.append(m)

    deduped.sort(key=lambda x: -x.confidence)

    ioc_summary = {
        "ip": len(iocs["ip"]),
        "domain": len(iocs["domain"]),
        "hash": len(iocs["hash"]),
    }

    cat_counts: dict[str, int] = {}
    for m in deduped:
        cat_counts[m.threat_category] = cat_counts.get(m.threat_category, 0) + 1

    high_conf = sum(1 for m in deduped if m.confidence >= 0.7)

    if any(m.severity == "critical" for m in deduped):
        level = "critical"
    elif high_conf >= 3 or any(m.severity == "high" for m in deduped):
        level = "high"
    elif deduped:
        level = "medium"
    else:
        level = "low"

    return ThreatIntelReport(
        total_events=len(events),
        iocs_extracted=sum(len(v) for v in iocs.values()),
        matches_found=len(deduped),
        matches=deduped,
        ioc_summary=ioc_summary,
        threat_categories=cat_counts,
        high_confidence_count=high_conf,
        overall_threat_level=level,
    )


def format_text(report: ThreatIntelReport) -> str:
    lines = [
        "Threat Intelligence Enrichment",
        "=" * 40,
        f"Events analyzed:       {report.total_events}",
        f"IOCs extracted:        {report.iocs_extracted}",
        f"Threat matches:        {report.matches_found}",
        f"High confidence:       {report.high_confidence_count}",
        f"Overall threat level:  {report.overall_threat_level}",
        "",
    ]
    if report.ioc_summary:
        lines.append("IOC Summary")
        lines.append("-" * 30)
        for ioc_type, count in sorted(report.ioc_summary.items()):
            lines.append(f"  {ioc_type:15s} {count}")
        lines.append("")

    if report.threat_categories:
        lines.append("Threat Categories")
        lines.append("-" * 30)
        for cat, count in sorted(report.threat_categories.items(), key=lambda x: -x[1]):
            lines.append(f"  {cat:25s} {count}")
        lines.append("")

    if report.matches:
        lines.append("Matches")
        lines.append("-" * 30)
        for m in report.matches:
            lines.append(f"  [{m.confidence:.2f}] [{m.severity:8s}] {m.ioc_type}: {m.ioc_value}")
            lines.append(f"    {m.description}")
            lines.append(f"    Source: {m.source}  Category: {m.threat_category}")
            lines.append("")

    return "\n".join(lines)


def format_json(report: ThreatIntelReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True)
