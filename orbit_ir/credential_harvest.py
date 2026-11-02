"""Credential harvesting detection for agent evidence.

Analyzes agent event sequences to detect credential harvesting patterns—
password extraction, key theft, token capture, credential dumping,
keylogging, phishing lures, and credential store access. Maps detections
to MITRE ATT&CK Credential Access techniques.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


MITRE_TECHNIQUES = {
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1003.002": "Security Account Manager",
    "T1003.003": "NTDS",
    "T1003.004": "LSA Secrets",
    "T1003.005": "Cached Domain Credentials",
    "T1003.006": "DCSync",
    "T1003.008": "/etc/passwd and /etc/shadow",
    "T1056": "Input Capture",
    "T1056.001": "Keylogging",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1110.002": "Password Cracking",
    "T1110.003": "Password Spraying",
    "T1539": "Steal Web Session Cookie",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Credentials In Files",
    "T1552.004": "Private Keys",
    "T1552.006": "Group Policy Preferences",
    "T1555": "Credentials from Password Stores",
    "T1555.001": "Keychain",
    "T1555.003": "Credentials from Web Browsers",
    "T1557": "Adversary-in-the-Middle",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.003": "Kerberoasting",
    "T1606": "Forge Web Credentials",
    "T1621": "Multi-Factor Authentication Request Generation",
}

DUMPING_TOOLS = {
    "mimikatz", "dump_hashes", "dump_creds", "hashdump", "secretsdump",
    "lsass_dump", "sam_dump", "ntds_dump", "dcsync", "pwdump",
    "credential_dump", "extract_hashes", "procdump", "comsvcs_dump",
    "dump_passwords", "lazagne", "pypykatz",
}

CREDENTIAL_FILE_TOOLS = {
    "read_file", "cat_file", "search_files", "grep_file", "find_creds",
    "read_config", "parse_config", "extract_keys",
}

CREDENTIAL_FILE_RE = re.compile(
    r"(\.pem\b|\.key\b|\.pfx\b|\.p12\b|id_rsa|id_ed25519|authorized_keys|"
    r"\.ssh/|credentials|\.aws/|\.env\b|password|shadow\b|passwd\b|"
    r"\.kdbx\b|\.keychain|web_credentials|login\.keychain|"
    r"\.netrc|\.pgpass|\.my\.cnf|\.boto|\.s3cfg)",
    re.IGNORECASE,
)

KEYLOG_TOOLS = {
    "keylogger", "capture_input", "log_keystrokes", "input_capture",
    "hook_keyboard", "record_input", "sniff_input",
}

BRUTE_FORCE_TOOLS = {
    "brute_force", "password_spray", "guess_password", "crack_hash",
    "hydra", "medusa", "john", "hashcat", "ncrack", "patator",
    "crowbar", "spray_password",
}

TOKEN_THEFT_TOOLS = {
    "steal_token", "extract_token", "capture_cookie", "steal_cookie",
    "intercept_token", "forge_token", "clone_session", "hijack_session",
    "steal_session", "extract_jwt", "dump_tokens",
}

KERBEROS_TOOLS = {
    "kerberoast", "asreproast", "get_tgt", "request_ticket",
    "forge_ticket", "golden_ticket", "silver_ticket", "overpass_hash",
    "rubeus", "gettgt", "getst",
}

MFA_TOOLS = {
    "mfa_fatigue", "mfa_bomb", "push_spam", "otp_intercept",
    "bypass_mfa", "steal_totp", "phish_mfa",
}

HARVESTING_CATEGORIES = {
    "credential-dump": "OS credential dumping or memory extraction",
    "file-credential": "Credentials found in files or configuration",
    "keylogging": "Input capture or keystroke logging",
    "brute-force": "Password guessing, cracking, or spraying",
    "token-theft": "Session token or cookie theft",
    "kerberos": "Kerberos ticket theft or forging",
    "mfa-bypass": "Multi-factor authentication bypass or fatigue",
}


@dataclass
class HarvestDetection:
    detection_id: str
    agent_id: str
    category: str
    technique_id: str
    technique_name: str
    severity: str
    tool_used: str
    resource: str
    effect: str
    timestamp: str
    confidence: str
    description: str


@dataclass
class HarvestSummary:
    total_detections: int
    by_category: dict[str, int]
    by_severity: dict[str, int]
    by_technique: dict[str, int]
    agents_involved: int
    credential_types_targeted: list[str]


@dataclass
class HarvestReport:
    detections: list[HarvestDetection]
    summary: HarvestSummary
    agents_involved: list[str]


def _get_tool(ev: dict[str, Any]) -> str:
    return ev.get("tool", ev.get("claimed_tool", ev.get("actual_tool", "")))


def _classify_harvest(tool: str, resource: str, effect: str) -> tuple[str, str, str, str] | None:
    lower_tool = tool.lower()
    lower_resource = resource.lower()
    lower_effect = effect.lower()
    combined = f"{lower_tool} {lower_resource} {lower_effect}"

    if lower_tool in DUMPING_TOOLS:
        if "lsass" in combined:
            return "credential-dump", "T1003.001", "LSASS Memory", "critical"
        if "sam" in combined:
            return "credential-dump", "T1003.002", "Security Account Manager", "critical"
        if "ntds" in combined:
            return "credential-dump", "T1003.003", "NTDS", "critical"
        if "lsa" in combined:
            return "credential-dump", "T1003.004", "LSA Secrets", "critical"
        if "dcsync" in combined:
            return "credential-dump", "T1003.006", "DCSync", "critical"
        if "shadow" in combined or "passwd" in combined:
            return "credential-dump", "T1003.008", "/etc/passwd and /etc/shadow", "high"
        return "credential-dump", "T1003", "OS Credential Dumping", "critical"

    if lower_tool in CREDENTIAL_FILE_TOOLS and CREDENTIAL_FILE_RE.search(combined):
        if "keychain" in combined:
            return "file-credential", "T1555.001", "Keychain", "high"
        if "browser" in combined or "web_credentials" in combined:
            return "file-credential", "T1555.003", "Credentials from Web Browsers", "high"
        if any(k in combined for k in (".pem", ".pfx", "id_rsa", "id_ed25519", ".p12")):
            return "file-credential", "T1552.004", "Private Keys", "high"
        if ".key" in combined and ".keychain" not in combined:
            return "file-credential", "T1552.004", "Private Keys", "high"
        return "file-credential", "T1552.001", "Credentials In Files", "medium"

    if lower_tool in KEYLOG_TOOLS:
        return "keylogging", "T1056.001", "Keylogging", "high"

    if lower_tool in BRUTE_FORCE_TOOLS:
        if "spray" in combined:
            return "brute-force", "T1110.003", "Password Spraying", "high"
        if "crack" in combined or "hashcat" in combined or "john" in combined:
            return "brute-force", "T1110.002", "Password Cracking", "medium"
        return "brute-force", "T1110.001", "Password Guessing", "medium"

    if lower_tool in TOKEN_THEFT_TOOLS:
        if "cookie" in combined:
            return "token-theft", "T1539", "Steal Web Session Cookie", "high"
        if "forge" in combined:
            return "token-theft", "T1606", "Forge Web Credentials", "critical"
        return "token-theft", "T1539", "Steal Web Session Cookie", "high"

    if lower_tool in KERBEROS_TOOLS:
        if "kerberoast" in combined:
            return "kerberos", "T1558.003", "Kerberoasting", "high"
        if "golden" in combined:
            return "kerberos", "T1558", "Steal or Forge Kerberos Tickets", "critical"
        return "kerberos", "T1558", "Steal or Forge Kerberos Tickets", "high"

    if lower_tool in MFA_TOOLS:
        return "mfa-bypass", "T1621", "Multi-Factor Authentication Request Generation", "high"

    if CREDENTIAL_FILE_RE.search(combined) and any(
        k in lower_effect for k in ("read", "extract", "dump", "copy", "exfil")
    ):
        return "file-credential", "T1552.001", "Credentials In Files", "medium"

    return None


def _assess_confidence(ev: dict[str, Any], category: str) -> str:
    tool = _get_tool(ev)
    if tool in DUMPING_TOOLS | KERBEROS_TOOLS | MFA_TOOLS:
        return "high"
    if tool in TOKEN_THEFT_TOOLS | KEYLOG_TOOLS:
        return "high"
    if tool in BRUTE_FORCE_TOOLS:
        return "medium"
    return "low"


def analyze_harvest(events: list[dict[str, Any]]) -> HarvestReport:
    detections: list[HarvestDetection] = []
    all_agents: set[str] = set()
    detection_counter = 0

    for ev in events:
        tool = _get_tool(ev)
        resource = ev.get("resource", "")
        effect = ev.get("effect", "")
        agent_id = ev.get("agent_id", ev.get("agent", "unknown"))

        classification = _classify_harvest(tool, resource, effect)
        if classification is None:
            continue

        category, technique_id, technique_name, severity = classification
        all_agents.add(agent_id)
        detection_counter += 1

        detections.append(HarvestDetection(
            detection_id=f"harvest-{detection_counter:04d}",
            agent_id=agent_id,
            category=category,
            technique_id=technique_id,
            technique_name=technique_name,
            severity=severity,
            tool_used=tool,
            resource=resource,
            effect=effect,
            timestamp=ev.get("timestamp", ev.get("ts", "")),
            confidence=_assess_confidence(ev, category),
            description=HARVESTING_CATEGORIES.get(category, category),
        ))

    cat_counts: dict[str, int] = defaultdict(int)
    sev_counts: dict[str, int] = defaultdict(int)
    tech_counts: dict[str, int] = defaultdict(int)
    cred_types: set[str] = set()

    for d in detections:
        cat_counts[d.category] += 1
        sev_counts[d.severity] += 1
        tech_counts[d.technique_id] += 1
        cred_types.add(d.category)

    return HarvestReport(
        detections=detections,
        summary=HarvestSummary(
            total_detections=len(detections),
            by_category=dict(cat_counts),
            by_severity=dict(sev_counts),
            by_technique=dict(tech_counts),
            agents_involved=len(all_agents),
            credential_types_targeted=sorted(cred_types),
        ),
        agents_involved=sorted(all_agents),
    )


def _load_events(evidence_dir: Path) -> list[dict[str, Any]]:
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


def format_text(report: HarvestReport) -> str:
    lines: list[str] = []
    lines.append("Credential Harvesting Detection Report")
    lines.append("=" * 62)
    lines.append("")
    lines.append(f"  Total detections:       {report.summary.total_detections}")
    lines.append(f"  Agents involved:        {report.summary.agents_involved}")
    lines.append(f"  Credential types:       {len(report.summary.credential_types_targeted)}")
    lines.append("")

    if report.summary.by_category:
        lines.append("  Categories:")
        for cat, count in sorted(report.summary.by_category.items(), key=lambda x: -x[1]):
            lines.append(f"    {cat:<25s} {count}")
        lines.append("")

    if report.summary.by_severity:
        lines.append("  Severity distribution:")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for sev, count in sorted(report.summary.by_severity.items(), key=lambda x: order.get(x[0], 9)):
            lines.append(f"    {sev:<15s} {count}")
        lines.append("")

    if report.detections:
        lines.append("  Detections:")
        for d in report.detections:
            lines.append(f"    [{d.severity.upper()}] {d.detection_id}: "
                         f"{d.category} — {d.technique_name} ({d.technique_id})")
            lines.append(f"      Agent: {d.agent_id}  Tool: {d.tool_used}")
        lines.append("")

    return "\n".join(lines) + "\n"


def format_json(report: HarvestReport) -> str:
    return json.dumps(asdict(report), indent=2) + "\n"
