"""Sandbox escape attempt detection for agent evidence.

Analyzes agent events for indicators of sandbox or container escape
attempts—privileged operations, mount namespace manipulation, kernel
exploit signatures, and container breakout indicators.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


ESCAPE_TYPES = {
    "privileged-op": "Attempted privileged syscall or capability outside sandbox",
    "mount-escape": "Mount namespace manipulation or host filesystem access",
    "kernel-exploit": "Pattern matching known kernel exploit signatures",
    "container-breakout": "Container escape via docker socket or host access",
}

PRIVILEGED_OPS = {
    "ptrace", "mount", "umount", "mknod", "chroot", "pivot_root",
    "setns", "unshare", "capset", "sethostname", "reboot",
    "init_module", "finit_module", "kexec_load", "bpf",
}

MOUNT_ESCAPE_PATTERNS = {
    "/proc/", "/sys/", "/dev/", "/host/", "/../../../",
    "/var/run/docker.sock", "/run/containerd/",
    "/etc/shadow", "/etc/passwd", "/root/",
}

KERNEL_EXPLOIT_SIGS = {
    "dirty_pipe", "dirty_cow", "overlayfs", "cve-2022-0847",
    "cve-2016-5195", "cve-2021-22555", "cve-2022-0185",
    "nsfs", "userfaultfd", "io_uring",
}

BREAKOUT_INDICATORS = {
    "docker.sock", "containerd.sock", "cri-o.sock",
    "nsenter", "runc", "ctr", "crictl",
    "/proc/1/root", "/proc/sysrq-trigger",
    "host_pid", "host_network", "host_ipc",
}


@dataclass
class EscapeDetection:
    detection_id: str
    agent_id: str
    escape_type: str
    severity: str
    confidence: str
    timestamp: str
    tool: str
    resource: str
    description: str
    evidence: dict = field(default_factory=dict)


@dataclass
class AgentRiskScore:
    agent_id: str
    total_attempts: int
    escape_types: list[str]
    risk_score: float
    highest_severity: str


@dataclass
class EscapeSummary:
    total_detections: int
    agents_involved: int
    escape_types_found: list[str]
    highest_severity: str


@dataclass
class EscapeReport:
    detections: list[EscapeDetection]
    summary: EscapeSummary
    agent_risk_scores: list[AgentRiskScore]


_counter = 0


def _next_id() -> str:
    global _counter
    _counter += 1
    return f"ESC-{_counter:04d}"


def _severity_for_escape(escape_type: str, resource: str) -> str:
    if escape_type == "kernel-exploit":
        return "critical"
    if escape_type == "container-breakout":
        if any(s in resource.lower() for s in ("docker.sock", "containerd.sock", "/proc/1/root")):
            return "critical"
        return "high"
    if escape_type == "mount-escape":
        if any(p in resource.lower() for p in ("/etc/shadow", "/etc/passwd", "/root/")):
            return "critical"
        return "high"
    if escape_type == "privileged-op":
        return "high"
    return "medium"


def _confidence_for_escape(escape_type: str, evidence_strength: int) -> str:
    if evidence_strength >= 3:
        return "high"
    if evidence_strength >= 2 or escape_type in ("kernel-exploit", "container-breakout"):
        return "high"
    if evidence_strength >= 1:
        return "medium"
    return "low"


def _detect_privileged_ops(events: list[dict]) -> list[EscapeDetection]:
    detections = []
    for ev in events:
        tool = ev.get("tool", "").lower()
        resource = ev.get("resource", "").lower()
        params = ev.get("parameters", {})
        syscall = ev.get("syscall", "").lower()

        matched_ops = []
        if syscall in PRIVILEGED_OPS:
            matched_ops.append(syscall)
        for op in PRIVILEGED_OPS:
            if op in tool or op in resource:
                matched_ops.append(op)
        if params:
            for v in params.values():
                sv = str(v).lower()
                for op in PRIVILEGED_OPS:
                    if op in sv:
                        matched_ops.append(op)

        if not matched_ops:
            continue

        sandbox = ev.get("sandbox", True)
        if sandbox is False:
            continue

        sev = _severity_for_escape("privileged-op", resource)
        conf = _confidence_for_escape("privileged-op", len(matched_ops))
        detections.append(EscapeDetection(
            detection_id=_next_id(),
            agent_id=ev.get("agent_id", "unknown"),
            escape_type="privileged-op",
            severity=sev,
            confidence=conf,
            timestamp=ev.get("timestamp", ""),
            tool=ev.get("tool", ""),
            resource=ev.get("resource", ""),
            description=f"Privileged operation attempt: {', '.join(set(matched_ops))}",
            evidence={"matched_ops": list(set(matched_ops))},
        ))
    return detections


def _detect_mount_escape(events: list[dict]) -> list[EscapeDetection]:
    detections = []
    for ev in events:
        resource = ev.get("resource", "")
        tool = ev.get("tool", "").lower()
        params = ev.get("parameters", {})
        rl = resource.lower()

        matches = []
        for pat in MOUNT_ESCAPE_PATTERNS:
            if pat.lower() in rl:
                matches.append(pat)
        if "mount" in tool or "bind" in tool:
            matches.append(tool)
        if params:
            for v in params.values():
                sv = str(v).lower()
                for pat in MOUNT_ESCAPE_PATTERNS:
                    if pat.lower() in sv:
                        matches.append(pat)

        if not matches:
            continue

        sev = _severity_for_escape("mount-escape", resource)
        conf = _confidence_for_escape("mount-escape", len(matches))
        detections.append(EscapeDetection(
            detection_id=_next_id(),
            agent_id=ev.get("agent_id", "unknown"),
            escape_type="mount-escape",
            severity=sev,
            confidence=conf,
            timestamp=ev.get("timestamp", ""),
            tool=ev.get("tool", ""),
            resource=resource,
            description=f"Mount escape attempt targeting: {', '.join(set(matches[:3]))}",
            evidence={"matched_patterns": list(set(matches))},
        ))
    return detections


def _detect_kernel_exploit(events: list[dict]) -> list[EscapeDetection]:
    detections = []
    for ev in events:
        resource = ev.get("resource", "").lower()
        tool = ev.get("tool", "").lower()
        desc_field = ev.get("description", "").lower()
        params = ev.get("parameters", {})

        matches = []
        for sig in KERNEL_EXPLOIT_SIGS:
            if sig in resource or sig in tool or sig in desc_field:
                matches.append(sig)
        if params:
            for v in params.values():
                sv = str(v).lower()
                for sig in KERNEL_EXPLOIT_SIGS:
                    if sig in sv:
                        matches.append(sig)

        if not matches:
            continue

        sev = _severity_for_escape("kernel-exploit", ev.get("resource", ""))
        conf = _confidence_for_escape("kernel-exploit", len(matches))
        detections.append(EscapeDetection(
            detection_id=_next_id(),
            agent_id=ev.get("agent_id", "unknown"),
            escape_type="kernel-exploit",
            severity=sev,
            confidence=conf,
            timestamp=ev.get("timestamp", ""),
            tool=ev.get("tool", ""),
            resource=ev.get("resource", ""),
            description=f"Kernel exploit signature detected: {', '.join(set(matches))}",
            evidence={"matched_signatures": list(set(matches))},
        ))
    return detections


def _detect_container_breakout(events: list[dict]) -> list[EscapeDetection]:
    detections = []
    for ev in events:
        resource = ev.get("resource", "").lower()
        tool = ev.get("tool", "").lower()
        params = ev.get("parameters", {})

        matches = []
        for ind in BREAKOUT_INDICATORS:
            if ind in resource or ind in tool:
                matches.append(ind)
        if params:
            for v in params.values():
                sv = str(v).lower()
                for ind in BREAKOUT_INDICATORS:
                    if ind in sv:
                        matches.append(ind)

        if not matches:
            continue

        sev = _severity_for_escape("container-breakout", ev.get("resource", ""))
        conf = _confidence_for_escape("container-breakout", len(matches))
        detections.append(EscapeDetection(
            detection_id=_next_id(),
            agent_id=ev.get("agent_id", "unknown"),
            escape_type="container-breakout",
            severity=sev,
            confidence=conf,
            timestamp=ev.get("timestamp", ""),
            tool=ev.get("tool", ""),
            resource=ev.get("resource", ""),
            description=f"Container breakout indicator: {', '.join(set(matches[:3]))}",
            evidence={"matched_indicators": list(set(matches))},
        ))
    return detections


def _build_agent_scores(detections: list[EscapeDetection]) -> list[AgentRiskScore]:
    by_agent: dict[str, list[EscapeDetection]] = defaultdict(list)
    for d in detections:
        by_agent[d.agent_id].append(d)

    sev_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    scores = []
    for agent_id, dets in sorted(by_agent.items()):
        types = list({d.escape_type for d in dets})
        total = len(dets)
        w = sum(sev_weights.get(d.severity, 1) for d in dets)
        risk = min(10.0, w * (1 + 0.2 * len(types)))
        highest = "low"
        for d in dets:
            if sev_weights.get(d.severity, 0) > sev_weights.get(highest, 0):
                highest = d.severity
        scores.append(AgentRiskScore(
            agent_id=agent_id,
            total_attempts=total,
            escape_types=types,
            risk_score=round(risk, 2),
            highest_severity=highest,
        ))
    scores.sort(key=lambda s: s.risk_score, reverse=True)
    return scores


def analyze_sandbox_escape(events: list[dict]) -> EscapeReport:
    global _counter
    _counter = 0

    all_detections: list[EscapeDetection] = []
    all_detections.extend(_detect_privileged_ops(events))
    all_detections.extend(_detect_mount_escape(events))
    all_detections.extend(_detect_kernel_exploit(events))
    all_detections.extend(_detect_container_breakout(events))

    agents = {d.agent_id for d in all_detections}
    types_found = sorted({d.escape_type for d in all_detections})

    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    highest = "low"
    for d in all_detections:
        if sev_order.get(d.severity, 0) > sev_order.get(highest, 0):
            highest = d.severity
    if not all_detections:
        highest = "none"

    summary = EscapeSummary(
        total_detections=len(all_detections),
        agents_involved=len(agents),
        escape_types_found=types_found,
        highest_severity=highest,
    )

    return EscapeReport(
        detections=all_detections,
        summary=summary,
        agent_risk_scores=_build_agent_scores(all_detections),
    )


def format_text(report: EscapeReport) -> str:
    lines = ["=== Sandbox Escape Detection Report ===", ""]
    s = report.summary
    lines.append(f"Total detections: {s.total_detections}")
    lines.append(f"Agents involved:  {s.agents_involved}")
    lines.append(f"Escape types:     {', '.join(s.escape_types_found) if s.escape_types_found else 'none'}")
    lines.append(f"Highest severity: {s.highest_severity}")
    lines.append("")

    if report.detections:
        lines.append("--- Detections ---")
        for d in report.detections:
            lines.append(f"  [{d.detection_id}] {d.escape_type} | {d.severity} | {d.confidence} confidence")
            lines.append(f"    Agent: {d.agent_id}  Tool: {d.tool}  Resource: {d.resource}")
            lines.append(f"    {d.description}")
            lines.append(f"    Time: {d.timestamp}")
            lines.append("")

    if report.agent_risk_scores:
        lines.append("--- Agent Risk Scores ---")
        for a in report.agent_risk_scores:
            lines.append(f"  {a.agent_id}: risk={a.risk_score}  attempts={a.total_attempts}  "
                         f"highest={a.highest_severity}  types={', '.join(a.escape_types)}")
        lines.append("")

    return "\n".join(lines)


def format_json(report: EscapeReport) -> str:
    data = {
        "detections": [asdict(d) for d in report.detections],
        "summary": asdict(report.summary),
        "agent_risk_scores": [asdict(a) for a in report.agent_risk_scores],
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
