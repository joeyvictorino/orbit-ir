"""Tests for ransomware behavior detection module."""

import json
import os
import tempfile

from orbit_ir.ransomware_behavior import (
    CATEGORIES,
    analyze,
    classify_event,
    format_report,
    load_events,
)


def test_file_encryption_burst_detected():
    ev = {"message": "Mass file encryption burst detected across network shares", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] == "file_encryption_burst"
    assert result["confidence"] > 0


def test_aes_encryption_detected():
    ev = {"message": "AES256 encrypting files on volume C: rapidly", "agent_id": "a1"}
    result = classify_event(ev)
    assert "file_encryption_burst" in result["indicators"]


def test_ransom_note_drop_detected():
    ev = {"message": "Ransom note created: how_to_decrypt.txt dropped in every directory", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] == "ransom_note_drop"


def test_how_to_decrypt_detected():
    ev = {"message": "File how.to.decrypt.html found on desktop after encryption", "agent_id": "a1"}
    result = classify_event(ev)
    assert "ransom_note_drop" in result["indicators"]


def test_shadow_copy_delete_detected():
    ev = {"message": "vssadmin delete shadows /all /quiet executed by agent", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] == "shadow_copy_delete"


def test_bcdedit_recovery_detected():
    ev = {"message": "bcdedit set recoveryenabled no executed to prevent recovery", "agent_id": "a1"}
    result = classify_event(ev)
    assert "shadow_copy_delete" in result["indicators"]


def test_extension_rename_detected():
    ev = {"message": "Bulk file rename of extensions to .encrypted variants", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] == "extension_rename"


def test_locked_extension_detected():
    ev = {"message": "Files renamed with .locked extension appended by ransomware", "agent_id": "a1"}
    result = classify_event(ev)
    assert "extension_rename" in result["indicators"]


def test_key_exfiltration_detected():
    ev = {"message": "Encryption key exfiltrated to C2 server via HTTPS POST", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] == "key_exfiltration"


def test_rsa_key_send_detected():
    ev = {"message": "RSA key generated and uploaded to remote command server", "agent_id": "a1"}
    result = classify_event(ev)
    assert "key_exfiltration" in result["indicators"]


def test_backup_destruction_detected():
    ev = {"message": "Backup deleted and recovery service disabled by agent", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] == "backup_destruction"


def test_wbadmin_delete_detected():
    ev = {"message": "wbadmin delete catalog -quiet to remove backup catalog", "agent_id": "a1"}
    result = classify_event(ev)
    assert "backup_destruction" in result["indicators"]


def test_no_ransomware_events():
    events = [{"message": "normal file read operation", "agent_id": "a1"}]
    result = analyze(events)
    assert result["ransomware_events"] == 0
    assert result["risk_level"] == "none"


def test_empty_events():
    result = analyze([])
    assert result["total_events"] == 0
    assert result["ransomware_events"] == 0
    assert result["risk_score"] == 0.0


def test_risk_score_calculated():
    events = [
        {"message": "Mass file encryption burst on server", "agent_id": "a1"},
        {"message": "vssadmin delete shadows executed", "agent_id": "a1"},
        {"message": "Ransom note created README_DECRYPT.txt", "agent_id": "a1"},
    ]
    result = analyze(events)
    assert result["risk_score"] > 0
    assert result["ransomware_events"] >= 2


def test_agents_tracked():
    events = [
        {"message": "Mass file encryption burst detected", "agent_id": "agent-1"},
        {"message": "Backup deleted by rogue process", "agent_id": "agent-2"},
    ]
    result = analyze(events)
    assert "agent-1" in result["agents_involved"]
    assert "agent-2" in result["agents_involved"]


def test_attack_chains():
    events = [
        {"message": "Shadow copy delete via vssadmin", "agent_id": "attacker"},
        {"message": "Mass file encryption burst started", "agent_id": "attacker"},
        {"message": "Ransom note dropped in directories", "agent_id": "attacker"},
    ]
    result = analyze(events)
    chains = result.get("attack_chains", [])
    assert len(chains) >= 1
    assert chains[0]["agent"] == "attacker"


def test_classify_event_no_match():
    ev = {"message": "system health check passed", "agent_id": "monitor"}
    result = classify_event(ev)
    assert result["category"] == ""
    assert result["confidence"] == 0.0
    assert result["indicators"] == []


def test_classify_event_with_match():
    ev = {"message": "Bulk file encryption cipher operation started by agent", "agent_id": "a1"}
    result = classify_event(ev)
    assert result["category"] != ""
    assert result["confidence"] > 0


def test_format_report_output():
    events = [
        {"message": "Mass file encryption burst on share", "agent_id": "a1"},
        {"message": "vssadmin delete shadows /all", "agent_id": "a1"},
    ]
    result = analyze(events)
    text = format_report(result)
    assert "Ransomware Behavior" in text
    assert "Risk score" in text


def test_format_report_empty():
    result = analyze([])
    text = format_report(result)
    assert "Total events: 0" in text


def test_load_events_file():
    data = [{"message": "test event", "agent_id": "a1"}]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.flush()
        path = f.name
    try:
        events = load_events(path)
        assert len(events) == 1
        assert events[0]["message"] == "test event"
    finally:
        os.unlink(path)


def test_load_events_missing():
    events = load_events("/nonexistent/path/events.json")
    assert events == []


def test_load_events_directory():
    with tempfile.TemporaryDirectory() as d:
        data = [{"message": "dir event"}]
        p = os.path.join(d, "ev1.json")
        with open(p, "w") as f:
            json.dump(data, f)
        events = load_events(d)
        assert len(events) == 1


def test_multiple_categories_single_event():
    ev = {
        "message": "Mass file encryption burst then backup deleted and destroyed",
        "agent_id": "a1",
    }
    result = classify_event(ev)
    assert len(result["indicators"]) >= 2


def test_file_count_tracked():
    events = [{"message": "Bulk file encryption operation", "agent_id": "a1", "file_count": 1500}]
    result = analyze(events)
    cats = [c for c in result["categories"] if c["count"] > 0]
    assert len(cats) >= 1


def test_all_categories_defined():
    expected = {
        "file_encryption_burst", "ransom_note_drop", "shadow_copy_delete",
        "extension_rename", "key_exfiltration", "backup_destruction",
    }
    assert set(CATEGORIES.keys()) == expected
