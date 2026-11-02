"""Supply chain attack pattern detection for agent evidence.

Analyzes agent events for indicators of supply chain attacks—dependency
confusion, compromised package installations, malicious update patterns,
and typosquatting attempts.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


ATTACK_TYPES = {
    "dependency-confusion": "Internal package name resolved to public registry",
    "compromised-package": "Installation of known-malicious or suspicious package",
    "malicious-update": "Package update with suspicious version jump or payload",
    "typosquat": "Package name similar to popular package (potential typosquat)",
}

SUSPICIOUS_INSTALL_TOOLS = {
    "pip_install", "npm_install", "install_package", "add_dependency",
    "cargo_add", "go_get", "gem_install", "composer_require",
    "execute_command", "run_shell",
}

KNOWN_MALICIOUS_PATTERNS = {
    "preinstall", "postinstall", "eval(", "exec(",
    "base64_decode", "subprocess.call", "os.system",
    "child_process", "curl |", "wget |",
}

POPULAR_PACKAGES = {
    "requests", "numpy", "pandas", "flask", "django", "express",
    "react", "lodash", "axios", "tensorflow", "torch", "boto3",
    "urllib3", "cryptography", "pillow", "setuptools",
}

INTERNAL_REGISTRY_PATTERNS = {
    "internal.", "corp.", "private.", "registry.local",
    ".internal:", "artifactory.", "nexus.",
}


@dataclass
class SupplyChainDetection:
    detection_id: str
    agent_id: str
    attack_type: str
    severity: str
    confidence: str
    timestamp: str
    tool: str
    package: str
    description: str
    evidence: dict = field(default_factory=dict)


@dataclass
class AgentSupplyScore:
    agent_id: str
    total_detections: int
    attack_types: list[str]
    risk_score: float
    packages_flagged: list[str]


@dataclass
class SupplyChainSummary:
    total_detections: int
    agents_involved: int
    attack_types_found: list[str]
    packages_flagged: int
    highest_severity: str


@dataclass
class SupplyChainReport:
    detections: list[SupplyChainDetection]
    summary: SupplyChainSummary
    agent_scores: list[AgentSupplyScore]


_counter = 0


def _next_id() -> str:
    global _counter
    _counter += 1
    return f"SC-{_counter:04d}"


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (0 if ca == cb else 1)))
        prev = curr
    return prev[-1]


def _is_typosquat(name: str) -> str | None:
    nl = name.lower().strip()
    for pop in POPULAR_PACKAGES:
        if nl == pop:
            continue
        dist = _levenshtein(nl, pop)
        if 0 < dist <= 2 and len(nl) >= 3:
            return pop
    return None


def _extract_package(event: dict) -> str:
    pkg = event.get("package", "")
    if pkg:
        return pkg
    resource = event.get("resource", "")
    if resource:
        parts = resource.split()
        for p in parts:
            if p and not p.startswith("-") and not p.startswith("/"):
                return p
    return ""


def _severity_for_attack(attack_type: str, evidence_count: int) -> str:
    if attack_type == "compromised-package":
        return "critical"
    if attack_type == "dependency-confusion":
        return "critical" if evidence_count >= 2 else "high"
    if attack_type == "malicious-update":
        return "high"
    if attack_type == "typosquat":
        return "high" if evidence_count >= 2 else "medium"
    return "medium"


def _detect_dependency_confusion(events: list[dict]) -> list[SupplyChainDetection]:
    detections = []
    for ev in events:
        registry = ev.get("registry", "").lower()
        resource = ev.get("resource", "").lower()
        internal = ev.get("internal_package", False)

        is_internal = internal
        if not is_internal:
            for pat in INTERNAL_REGISTRY_PATTERNS:
                if pat in resource:
                    is_internal = True
                    break

        public_registry = ev.get("public_registry", False)
        if not public_registry and registry:
            public_registry = any(r in registry for r in ("pypi.org", "npmjs.com", "registry.npmjs", "crates.io", "rubygems.org"))

        if is_internal and public_registry:
            pkg = _extract_package(ev)
            sev = _severity_for_attack("dependency-confusion", 2)
            detections.append(SupplyChainDetection(
                detection_id=_next_id(),
                agent_id=ev.get("agent_id", "unknown"),
                attack_type="dependency-confusion",
                severity=sev,
                confidence="high",
                timestamp=ev.get("timestamp", ""),
                tool=ev.get("tool", ""),
                package=pkg,
                description=f"Internal package '{pkg}' resolved from public registry '{registry}'",
                evidence={"registry": registry, "internal_package": True},
            ))
    return detections


def _detect_compromised_package(events: list[dict]) -> list[SupplyChainDetection]:
    detections = []
    for ev in events:
        tool = ev.get("tool", "").lower()
        resource = ev.get("resource", "").lower()
        params = ev.get("parameters", {})
        scripts = ev.get("scripts", {})

        if tool not in SUSPICIOUS_INSTALL_TOOLS and "install" not in tool:
            continue

        matches = []
        for pat in KNOWN_MALICIOUS_PATTERNS:
            if pat in resource:
                matches.append(pat)
            if scripts:
                for sv in scripts.values():
                    if pat in str(sv).lower():
                        matches.append(pat)
            if params:
                for pv in params.values():
                    if pat in str(pv).lower():
                        matches.append(pat)

        if not matches:
            continue

        pkg = _extract_package(ev)
        sev = _severity_for_attack("compromised-package", len(matches))
        detections.append(SupplyChainDetection(
            detection_id=_next_id(),
            agent_id=ev.get("agent_id", "unknown"),
            attack_type="compromised-package",
            severity=sev,
            confidence="high" if len(matches) >= 2 else "medium",
            timestamp=ev.get("timestamp", ""),
            tool=ev.get("tool", ""),
            package=pkg,
            description=f"Suspicious package install with malicious patterns: {', '.join(set(matches[:3]))}",
            evidence={"matched_patterns": list(set(matches))},
        ))
    return detections


def _detect_malicious_update(events: list[dict]) -> list[SupplyChainDetection]:
    detections = []
    pkg_versions: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        pkg = _extract_package(ev)
        version = ev.get("version", "")
        if pkg and version:
            pkg_versions[pkg].append(ev)

    for pkg, evs in pkg_versions.items():
        if len(evs) < 2:
            continue
        versions = [e.get("version", "") for e in evs]
        for i in range(1, len(versions)):
            prev_v = versions[i - 1]
            curr_v = versions[i]
            if not prev_v or not curr_v:
                continue
            try:
                prev_parts = [int(x) for x in prev_v.split(".")[:3]]
                curr_parts = [int(x) for x in curr_v.split(".")[:3]]
            except (ValueError, IndexError):
                continue
            if len(prev_parts) >= 1 and len(curr_parts) >= 1:
                if curr_parts[0] - prev_parts[0] >= 5:
                    ev = evs[i]
                    sev = _severity_for_attack("malicious-update", 1)
                    detections.append(SupplyChainDetection(
                        detection_id=_next_id(),
                        agent_id=ev.get("agent_id", "unknown"),
                        attack_type="malicious-update",
                        severity=sev,
                        confidence="medium",
                        timestamp=ev.get("timestamp", ""),
                        tool=ev.get("tool", ""),
                        package=pkg,
                        description=f"Suspicious version jump for '{pkg}': {prev_v} -> {curr_v}",
                        evidence={"prev_version": prev_v, "curr_version": curr_v},
                    ))
    return detections


def _detect_typosquat(events: list[dict]) -> list[SupplyChainDetection]:
    detections = []
    seen = set()
    for ev in events:
        tool = ev.get("tool", "").lower()
        if tool not in SUSPICIOUS_INSTALL_TOOLS and "install" not in tool:
            continue

        pkg = _extract_package(ev)
        if not pkg or pkg in seen:
            continue

        target = _is_typosquat(pkg)
        if target is None:
            continue
        seen.add(pkg)

        sev = _severity_for_attack("typosquat", 1)
        detections.append(SupplyChainDetection(
            detection_id=_next_id(),
            agent_id=ev.get("agent_id", "unknown"),
            attack_type="typosquat",
            severity=sev,
            confidence="medium",
            timestamp=ev.get("timestamp", ""),
            tool=ev.get("tool", ""),
            package=pkg,
            description=f"Possible typosquat: '{pkg}' is similar to popular package '{target}'",
            evidence={"similar_to": target, "distance": _levenshtein(pkg.lower(), target)},
        ))
    return detections


def _build_agent_scores(detections: list[SupplyChainDetection]) -> list[AgentSupplyScore]:
    by_agent: dict[str, list[SupplyChainDetection]] = defaultdict(list)
    for d in detections:
        by_agent[d.agent_id].append(d)

    sev_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    scores = []
    for agent_id, dets in sorted(by_agent.items()):
        types = list({d.attack_type for d in dets})
        pkgs = list({d.package for d in dets if d.package})
        w = sum(sev_weights.get(d.severity, 1) for d in dets)
        risk = min(10.0, w * (1 + 0.15 * len(types)))
        scores.append(AgentSupplyScore(
            agent_id=agent_id,
            total_detections=len(dets),
            attack_types=types,
            risk_score=round(risk, 2),
            packages_flagged=pkgs,
        ))
    scores.sort(key=lambda s: s.risk_score, reverse=True)
    return scores


def analyze_supply_chain(events: list[dict]) -> SupplyChainReport:
    global _counter
    _counter = 0

    all_detections: list[SupplyChainDetection] = []
    all_detections.extend(_detect_dependency_confusion(events))
    all_detections.extend(_detect_compromised_package(events))
    all_detections.extend(_detect_malicious_update(events))
    all_detections.extend(_detect_typosquat(events))

    agents = {d.agent_id for d in all_detections}
    types_found = sorted({d.attack_type for d in all_detections})
    pkgs = {d.package for d in all_detections if d.package}

    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    highest = "low"
    for d in all_detections:
        if sev_order.get(d.severity, 0) > sev_order.get(highest, 0):
            highest = d.severity
    if not all_detections:
        highest = "none"

    summary = SupplyChainSummary(
        total_detections=len(all_detections),
        agents_involved=len(agents),
        attack_types_found=types_found,
        packages_flagged=len(pkgs),
        highest_severity=highest,
    )

    return SupplyChainReport(
        detections=all_detections,
        summary=summary,
        agent_scores=_build_agent_scores(all_detections),
    )


def format_text(report: SupplyChainReport) -> str:
    lines = ["=== Supply Chain Attack Detection Report ===", ""]
    s = report.summary
    lines.append(f"Total detections:  {s.total_detections}")
    lines.append(f"Agents involved:   {s.agents_involved}")
    lines.append(f"Attack types:      {', '.join(s.attack_types_found) if s.attack_types_found else 'none'}")
    lines.append(f"Packages flagged:  {s.packages_flagged}")
    lines.append(f"Highest severity:  {s.highest_severity}")
    lines.append("")

    if report.detections:
        lines.append("--- Detections ---")
        for d in report.detections:
            lines.append(f"  [{d.detection_id}] {d.attack_type} | {d.severity} | {d.confidence} confidence")
            lines.append(f"    Agent: {d.agent_id}  Tool: {d.tool}  Package: {d.package}")
            lines.append(f"    {d.description}")
            lines.append(f"    Time: {d.timestamp}")
            lines.append("")

    if report.agent_scores:
        lines.append("--- Agent Scores ---")
        for a in report.agent_scores:
            lines.append(f"  {a.agent_id}: risk={a.risk_score}  detections={a.total_detections}  "
                         f"types={', '.join(a.attack_types)}  pkgs={', '.join(a.packages_flagged[:3])}")
        lines.append("")

    return "\n".join(lines)


def format_json(report: SupplyChainReport) -> str:
    data = {
        "detections": [asdict(d) for d in report.detections],
        "summary": asdict(report.summary),
        "agent_scores": [asdict(a) for a in report.agent_scores],
    }
    return json.dumps(data, indent=2)


def _load_events(path: str | Path) -> list[dict]:
    p = Path(path)
    if p.is_dir():
        events = []
        for f in sorted(p.glob("*.json")):
            events.extend(json.loads(f.read_text()))
        return events
    return json.loads(p.read_text())
