"""Tests for credential harvesting detection."""
from orbit_ir.credential_harvest import analyze_harvest, format_text, format_json


def _ev(agent, tool, resource="", effect="", ts="2025-01-01T00:00:00Z"):
    return {"agent_id": agent, "tool": tool, "resource": resource, "effect": effect, "timestamp": ts}


def test_empty_events():
    r = analyze_harvest([])
    assert r.summary.total_detections == 0
    assert r.summary.agents_involved == 0


def test_mimikatz_detection():
    events = [_ev("agent-a", "mimikatz", "lsass.exe")]
    r = analyze_harvest(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].category == "credential-dump"
    assert r.detections[0].technique_id == "T1003.001"
    assert r.detections[0].severity == "critical"


def test_sam_dump():
    events = [_ev("agent-a", "sam_dump", "SAM database")]
    r = analyze_harvest(events)
    assert r.detections[0].technique_id == "T1003.002"


def test_ntds_dump():
    events = [_ev("agent-a", "ntds_dump", "ntds.dit")]
    r = analyze_harvest(events)
    assert r.detections[0].technique_id == "T1003.003"


def test_dcsync():
    events = [_ev("agent-a", "dcsync", "domain controller")]
    r = analyze_harvest(events)
    assert r.detections[0].technique_id == "T1003.006"
    assert r.detections[0].severity == "critical"


def test_shadow_file():
    events = [_ev("agent-a", "dump_creds", "/etc/shadow")]
    r = analyze_harvest(events)
    assert r.detections[0].technique_id == "T1003.008"


def test_credential_file_private_key():
    events = [_ev("agent-a", "read_file", "/home/user/.ssh/id_rsa")]
    r = analyze_harvest(events)
    assert r.summary.total_detections == 1
    assert r.detections[0].category == "file-credential"
    assert r.detections[0].technique_id == "T1552.004"


def test_credential_file_keychain():
    events = [_ev("agent-a", "read_file", "/Users/admin/Library/Keychains/login.keychain")]
    r = analyze_harvest(events)
    assert r.detections[0].technique_id == "T1555.001"


def test_credential_file_browser():
    events = [_ev("agent-a", "read_file", "web_credentials database")]
    r = analyze_harvest(events)
    assert r.detections[0].technique_id == "T1555.003"


def test_credential_file_generic():
    events = [_ev("agent-a", "read_file", "/app/.env")]
    r = analyze_harvest(events)
    assert r.detections[0].category == "file-credential"
    assert r.detections[0].technique_id == "T1552.001"


def test_keylogging():
    events = [_ev("agent-a", "keylogger", "keyboard input")]
    r = analyze_harvest(events)
    assert r.detections[0].category == "keylogging"
    assert r.detections[0].technique_id == "T1056.001"


def test_brute_force_spray():
    events = [_ev("agent-a", "password_spray", "admin accounts")]
    r = analyze_harvest(events)
    assert r.detections[0].category == "brute-force"
    assert r.detections[0].technique_id == "T1110.003"


def test_brute_force_crack():
    events = [_ev("agent-a", "hashcat", "ntlm hashes", effect="crack passwords")]
    r = analyze_harvest(events)
    assert r.detections[0].technique_id == "T1110.002"


def test_brute_force_guess():
    events = [_ev("agent-a", "brute_force", "ssh login")]
    r = analyze_harvest(events)
    assert r.detections[0].technique_id == "T1110.001"


def test_token_theft_cookie():
    events = [_ev("agent-a", "steal_cookie", "session cookie")]
    r = analyze_harvest(events)
    assert r.detections[0].category == "token-theft"
    assert r.detections[0].technique_id == "T1539"


def test_token_theft_forge():
    events = [_ev("agent-a", "forge_token", "jwt token")]
    r = analyze_harvest(events)
    assert r.detections[0].technique_id == "T1606"
    assert r.detections[0].severity == "critical"


def test_kerberoasting():
    events = [_ev("agent-a", "kerberoast", "SPN accounts")]
    r = analyze_harvest(events)
    assert r.detections[0].category == "kerberos"
    assert r.detections[0].technique_id == "T1558.003"


def test_golden_ticket():
    events = [_ev("agent-a", "golden_ticket", "krbtgt")]
    r = analyze_harvest(events)
    assert r.detections[0].technique_id == "T1558"
    assert r.detections[0].severity == "critical"


def test_mfa_fatigue():
    events = [_ev("agent-a", "mfa_fatigue", "user@company.com")]
    r = analyze_harvest(events)
    assert r.detections[0].category == "mfa-bypass"
    assert r.detections[0].technique_id == "T1621"


def test_no_harvest_events():
    events = [_ev("agent-a", "list_files", "/tmp")]
    r = analyze_harvest(events)
    assert r.summary.total_detections == 0


def test_multiple_detections():
    events = [
        _ev("agent-a", "mimikatz", "lsass"),
        _ev("agent-b", "read_file", "/root/.ssh/id_rsa"),
        _ev("agent-a", "kerberoast", "SPNs"),
    ]
    r = analyze_harvest(events)
    assert r.summary.total_detections == 3
    assert r.summary.agents_involved == 2


def test_severity_distribution():
    events = [
        _ev("a", "mimikatz", "lsass"),
        _ev("a", "read_file", "/app/.env"),
    ]
    r = analyze_harvest(events)
    assert "critical" in r.summary.by_severity
    assert "medium" in r.summary.by_severity


def test_category_counts():
    events = [
        _ev("a", "mimikatz", "lsass"),
        _ev("a", "dump_hashes", "sam"),
        _ev("a", "read_file", "/root/.ssh/id_rsa"),
    ]
    r = analyze_harvest(events)
    assert r.summary.by_category.get("credential-dump", 0) == 2
    assert r.summary.by_category.get("file-credential", 0) == 1


def test_agents_list():
    events = [
        _ev("agent-x", "mimikatz", "lsass"),
        _ev("agent-y", "kerberoast", "SPNs"),
    ]
    r = analyze_harvest(events)
    assert "agent-x" in r.agents_involved
    assert "agent-y" in r.agents_involved


def test_confidence_high_for_dumping():
    events = [_ev("a", "mimikatz", "lsass")]
    r = analyze_harvest(events)
    assert r.detections[0].confidence == "high"


def test_format_text_output():
    events = [_ev("a", "mimikatz", "lsass")]
    r = analyze_harvest(events)
    text = format_text(r)
    assert "Credential Harvesting" in text
    assert "credential-dump" in text


def test_format_json_output():
    events = [_ev("a", "mimikatz", "lsass")]
    r = analyze_harvest(events)
    j = format_json(r)
    assert j.startswith("{")
    data = __import__("json").loads(j)
    assert "detections" in data
    assert "summary" in data


def test_credential_types_targeted():
    events = [
        _ev("a", "mimikatz", "lsass"),
        _ev("a", "kerberoast", "SPNs"),
        _ev("a", "read_file", "/app/.env"),
    ]
    r = analyze_harvest(events)
    assert len(r.summary.credential_types_targeted) >= 3
