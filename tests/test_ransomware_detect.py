"""Tests for ransomware behavior detection module."""

import json
import pytest
from orbit_ir.ransomware_detect import (
    CATEGORIES,
    analyze_ransomware,
    format_text,
    format_json,
    _classify_event,
    _detect_chains,
    _load_events,
)


def mk_event(action="", detail="", agent_id="agent-1", **kwargs):
    ev = {"action": action, "detail": detail, "agent_id": agent_id, "timestamp": "2024-01-01T00:00:00Z"}
    ev.update(kwargs)
    return ev


class TestCategories:
    def test_all_categories_have_patterns(self):
        for name, info in CATEGORIES.items():
            assert len(info["patterns"]) > 0, f"{name} has no patterns"

    def test_all_categories_have_severity(self):
        for name, info in CATEGORIES.items():
            assert info["severity"] in ("critical", "high", "medium", "low")

    def test_all_categories_have_description(self):
        for name, info in CATEGORIES.items():
            assert len(info["description"]) > 0


class TestFileEncryption:
    def test_mass_encryption(self):
        ev = mk_event(action="encrypt files mass bulk recursive detected")
        results = _classify_event(ev)
        assert any(r.category == "file_encryption" for r in results)

    def test_ransomware_encrypt(self):
        ev = mk_event(detail="ransomware encrypting attack detected payload launched")
        results = _classify_event(ev)
        assert any(r.category == "file_encryption" for r in results)

    def test_aes_encrypt(self):
        ev = mk_event(action="AES encryption file data operation detected")
        results = _classify_event(ev)
        assert any(r.category == "file_encryption" for r in results)

    def test_file_encrypt_detected(self):
        ev = mk_event(detail="file encrypted detected mass bulk recursive sweep")
        results = _classify_event(ev)
        assert any(r.category == "file_encryption" for r in results)


class TestRansomNote:
    def test_ransom_note_created(self):
        ev = mk_event(action="ransom note created on encrypted system")
        results = _classify_event(ev)
        assert any(r.category == "ransom_note" for r in results)

    def test_decrypt_instructions(self):
        ev = mk_event(detail="README decrypt payment bitcoin instructions left")
        results = _classify_event(ev)
        assert any(r.category == "ransom_note" for r in results)

    def test_extortion_message(self):
        ev = mk_event(action="created extortion message demand for payment")
        results = _classify_event(ev)
        assert any(r.category == "ransom_note" for r in results)

    def test_payment_demand(self):
        ev = mk_event(detail="payment bitcoin demand ransom decrypt recover files")
        results = _classify_event(ev)
        assert any(r.category == "ransom_note" for r in results)


class TestShadowDeletion:
    def test_shadow_copy_deleted(self):
        ev = mk_event(action="shadow copy deleted removed from system")
        results = _classify_event(ev)
        assert any(r.category == "shadow_deletion" for r in results)

    def test_vssadmin_delete(self):
        ev = mk_event(detail="vssadmin delete shadows backup detected on system")
        results = _classify_event(ev)
        assert any(r.category == "shadow_deletion" for r in results)

    def test_backup_deletion(self):
        ev = mk_event(action="backup recovery deletion detected on system")
        results = _classify_event(ev)
        assert any(r.category == "shadow_deletion" for r in results)

    def test_deleted_volume_shadow(self):
        ev = mk_event(detail="deleted volume shadow copy snapshot from system")
        results = _classify_event(ev)
        assert any(r.category == "shadow_deletion" for r in results)


class TestPrivilegeEscalation:
    def test_privilege_escalation(self):
        ev = mk_event(action="privilege escalation detected admin before encryption")
        results = _classify_event(ev)
        assert any(r.category == "privilege_escalation" for r in results)

    def test_exploit_escalation(self):
        ev = mk_event(detail="exploit privilege escalation detected local kernel")
        results = _classify_event(ev)
        assert any(r.category == "privilege_escalation" for r in results)

    def test_uac_bypass(self):
        ev = mk_event(action="UAC bypass detected escalation privilege ransom")
        results = _classify_event(ev)
        assert any(r.category == "privilege_escalation" for r in results)


class TestNetworkPropagation:
    def test_ransomware_spread(self):
        ev = mk_event(action="ransomware propagation network SMB share detected")
        results = _classify_event(ev)
        assert any(r.category == "network_propagation" for r in results)

    def test_lateral_movement(self):
        ev = mk_event(detail="lateral movement ransomware encrypt detected on network")
        results = _classify_event(ev)
        assert any(r.category == "network_propagation" for r in results)

    def test_smb_propagation(self):
        ev = mk_event(action="SMB propagating ransomware encrypt detected network")
        results = _classify_event(ev)
        assert any(r.category == "network_propagation" for r in results)

    def test_self_propagating(self):
        ev = mk_event(detail="self-propagating ransomware detected network wide")
        results = _classify_event(ev)
        assert any(r.category == "network_propagation" for r in results)


class TestExfiltrationThreat:
    def test_data_exfiltration(self):
        ev = mk_event(action="exfiltrating data before encrypt for extortion")
        results = _classify_event(ev)
        assert any(r.category == "exfiltration_threat" for r in results)

    def test_double_extortion(self):
        ev = mk_event(detail="double extortion detected scheme attack data theft")
        results = _classify_event(ev)
        assert any(r.category == "exfiltration_threat" for r in results)

    def test_data_theft(self):
        ev = mk_event(action="data theft extortion ransom detect in network")
        results = _classify_event(ev)
        assert any(r.category == "exfiltration_threat" for r in results)


class TestClassifyEvent:
    def test_empty_event(self):
        results = _classify_event({})
        assert results == []

    def test_benign_event(self):
        ev = mk_event(action="user deployed application")
        results = _classify_event(ev)
        assert results == []

    def test_severity_critical(self):
        ev = mk_event(action="encrypted data mass operation detected")
        results = _classify_event(ev)
        assert results[0].severity == "critical"

    def test_fields_populated(self):
        ev = mk_event(action="encrypted data mass operation detected", agent_id="ransom-42")
        results = _classify_event(ev)
        assert results[0].agent_id == "ransom-42"
        assert results[0].violation_type == "ransomware_activity"


class TestDetectChains:
    def test_single_chain(self):
        events = [
            mk_event(action="encrypted data mass operation detected"),
            mk_event(action="ransom note created on encrypted system"),
        ]
        violations = []
        for ev in events:
            violations.extend(_classify_event(ev))
        chains = _detect_chains(violations)
        assert len(chains) == 1
        assert chains[0].violation_score > 0

    def test_multi_agent_chains(self):
        events = [
            mk_event(action="encrypted data mass operation detected", agent_id="a1"),
            mk_event(action="ransom note created on encrypted system", agent_id="a2"),
        ]
        violations = []
        for ev in events:
            violations.extend(_classify_event(ev))
        chains = _detect_chains(violations)
        assert len(chains) == 2

    def test_score_bonus_encryption_plus_note(self):
        events1 = [mk_event(action="encrypted data mass operation detected")]
        events2 = [
            mk_event(action="encrypted data mass operation detected"),
            mk_event(action="ransom note created on encrypted system"),
        ]
        v1, v2 = [], []
        for ev in events1:
            v1.extend(_classify_event(ev))
        for ev in events2:
            v2.extend(_classify_event(ev))
        c1 = _detect_chains(v1)
        c2 = _detect_chains(v2)
        assert c2[0].violation_score > c1[0].violation_score


class TestAnalyzeRansomware:
    def test_empty(self):
        r = analyze_ransomware([])
        assert r.total_events == 0
        assert r.violation_events == 0

    def test_with_violations(self):
        events = [
            mk_event(action="encrypted data mass operation detected"),
            mk_event(action="ransom note created on encrypted system"),
        ]
        r = analyze_ransomware(events)
        assert r.total_events == 2
        assert r.violation_events >= 2

    def test_severity_counts(self):
        events = [mk_event(action="encrypted data mass operation detected")]
        r = analyze_ransomware(events)
        assert "critical" in r.severity_counts

    def test_agents_tracked(self):
        events = [
            mk_event(action="encrypted data mass operation detected", agent_id="a1"),
            mk_event(action="ransom note created on encrypted system", agent_id="a2"),
        ]
        r = analyze_ransomware(events)
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_benign_not_counted(self):
        events = [mk_event(action="normal application deployment")]
        r = analyze_ransomware(events)
        assert r.violation_events == 0


class TestFormatText:
    def test_header(self):
        r = analyze_ransomware([])
        text = format_text(r)
        assert "Ransomware Behavior Detection" in text

    def test_contains_counts(self):
        events = [mk_event(action="encrypted data mass operation detected")]
        r = analyze_ransomware(events)
        text = format_text(r)
        assert "Total events" in text

    def test_contains_category(self):
        events = [mk_event(action="encrypted data mass operation detected")]
        r = analyze_ransomware(events)
        text = format_text(r)
        assert "file_encryption" in text


class TestFormatJSON:
    def test_valid_json(self):
        events = [mk_event(action="encrypted data mass operation detected")]
        r = analyze_ransomware(events)
        out = format_json(r)
        data = json.loads(out)
        assert "total_events" in data

    def test_empty_valid(self):
        r = analyze_ransomware([])
        data = json.loads(format_json(r))
        assert data["total_events"] == 0

    def test_chains_in_output(self):
        events = [mk_event(action="encrypted data mass operation detected")]
        r = analyze_ransomware(events)
        data = json.loads(format_json(r))
        assert "chains" in data


class TestLoadEvents:
    def test_nonexistent(self):
        assert _load_events("/no/such/file.json") == []

    def test_list_format(self, tmp_path):
        f = tmp_path / "events.json"
        f.write_text(json.dumps([{"action": "test"}]))
        assert len(_load_events(str(f))) == 1

    def test_dict_format(self, tmp_path):
        f = tmp_path / "events.json"
        f.write_text(json.dumps({"events": [{"action": "test"}]}))
        assert len(_load_events(str(f))) == 1

    def test_single_event(self, tmp_path):
        f = tmp_path / "event.json"
        f.write_text(json.dumps({"action": "test"}))
        assert len(_load_events(str(f))) == 1
