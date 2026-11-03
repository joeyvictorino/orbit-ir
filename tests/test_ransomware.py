"""Tests for ransomware behavior detection module."""

import json
import pytest
from orbit_ir.ransomware import (
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
    def test_encrypt_files(self):
        ev = mk_event(action="encrypt files on disk")
        results = _classify_event(ev)
        assert any(r.category == "file_encryption" for r in results)

    def test_mass_encryption(self):
        ev = mk_event(detail="mass encrypt all documents in directory")
        results = _classify_event(ev)
        assert any(r.category == "file_encryption" for r in results)

    def test_ransomware_keyword(self):
        ev = mk_event(action="ransomware detected in system")
        results = _classify_event(ev)
        assert any(r.category == "file_encryption" for r in results)

    def test_aes_encryption(self):
        ev = mk_event(detail="AES encrypt key generation for files")
        results = _classify_event(ev)
        assert any(r.category == "file_encryption" for r in results)


class TestRansomNote:
    def test_ransom_note_creation(self):
        ev = mk_event(action="create ransom note on desktop")
        results = _classify_event(ev)
        assert any(r.category == "ransom_note" for r in results)

    def test_readme_decrypt(self):
        ev = mk_event(detail="README_DECRYPT file dropped")
        results = _classify_event(ev)
        assert any(r.category == "ransom_note" for r in results)

    def test_bitcoin_payment(self):
        ev = mk_event(detail="pay bitcoin to recover files")
        results = _classify_event(ev)
        assert any(r.category == "ransom_note" for r in results)

    def test_extortion_message(self):
        ev = mk_event(action="extortion message delivered to victim")
        results = _classify_event(ev)
        assert any(r.category == "ransom_note" for r in results)


class TestShadowDeletion:
    def test_delete_shadow_copies(self):
        ev = mk_event(action="delete shadow copies from system")
        results = _classify_event(ev)
        assert any(r.category == "shadow_deletion" for r in results)

    def test_vssadmin(self):
        ev = mk_event(detail="vssadmin delete shadows")
        results = _classify_event(ev)
        assert any(r.category == "shadow_deletion" for r in results)

    def test_disable_recovery(self):
        ev = mk_event(action="disable recovery mechanisms")
        results = _classify_event(ev)
        assert any(r.category == "shadow_deletion" for r in results)

    def test_destroy_backups(self):
        ev = mk_event(detail="destroy backup snapshots")
        results = _classify_event(ev)
        assert any(r.category == "shadow_deletion" for r in results)


class TestLateralSpread:
    def test_spread_to_systems(self):
        ev = mk_event(action="spread to adjacent systems via network")
        results = _classify_event(ev)
        assert any(r.category == "lateral_spread" for r in results)

    def test_network_worm(self):
        ev = mk_event(detail="self-propagating worm behavior detected")
        results = _classify_event(ev)
        assert any(r.category == "lateral_spread" for r in results)

    def test_smb_spread(self):
        ev = mk_event(action="SMB spread to lateral network shares")
        results = _classify_event(ev)
        assert any(r.category == "lateral_spread" for r in results)


class TestC2Ransom:
    def test_c2_communication(self):
        ev = mk_event(detail="command control server ransom key exchange")
        results = _classify_event(ev)
        assert any(r.category == "c2_ransom" for r in results)

    def test_double_extortion(self):
        ev = mk_event(action="double extortion attack campaign detected")
        results = _classify_event(ev)
        assert any(r.category == "c2_ransom" for r in results)


class TestKeyExfiltration:
    def test_key_exfil(self):
        ev = mk_event(action="exfiltrate encryption key to remote server")
        results = _classify_event(ev)
        assert any(r.category == "key_exfiltration" for r in results)

    def test_crypto_key_send(self):
        ev = mk_event(detail="send encryption key material to C2")
        results = _classify_event(ev)
        assert any(r.category == "key_exfiltration" for r in results)


class TestClassifyEvent:
    def test_empty_event(self):
        results = _classify_event({})
        assert results == []

    def test_benign_event(self):
        ev = mk_event(action="user logged in successfully")
        results = _classify_event(ev)
        assert results == []

    def test_severity_critical(self):
        ev = mk_event(action="encrypt files on disk")
        results = _classify_event(ev)
        assert results[0].severity == "critical"

    def test_event_fields_populated(self):
        ev = mk_event(action="encrypt files on disk", agent_id="agent-42")
        results = _classify_event(ev)
        assert results[0].agent_id == "agent-42"
        assert results[0].violation_type == "ransomware_behavior"


class TestDetectChains:
    def test_single_agent_chain(self):
        events = [
            mk_event(action="encrypt files on disk"),
            mk_event(action="create ransom note"),
        ]
        violations = []
        for ev in events:
            violations.extend(_classify_event(ev))
        chains = _detect_chains(violations)
        assert len(chains) == 1
        assert chains[0].violation_score > 0

    def test_multi_agent_chains(self):
        events = [
            mk_event(action="encrypt files on disk", agent_id="a1"),
            mk_event(action="create ransom note", agent_id="a2"),
        ]
        violations = []
        for ev in events:
            violations.extend(_classify_event(ev))
        chains = _detect_chains(violations)
        assert len(chains) == 2

    def test_chain_score_increases_with_categories(self):
        events1 = [mk_event(action="encrypt files on disk")]
        events2 = [
            mk_event(action="encrypt files on disk"),
            mk_event(action="create ransom note"),
            mk_event(action="delete shadow copies"),
        ]
        v1 = []
        for ev in events1:
            v1.extend(_classify_event(ev))
        v2 = []
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
            mk_event(action="encrypt files on disk"),
            mk_event(action="create ransom note on desktop"),
        ]
        r = analyze_ransomware(events)
        assert r.total_events == 2
        assert r.violation_events >= 2
        assert len(r.categories) > 0

    def test_severity_counts(self):
        events = [mk_event(action="encrypt files on disk")]
        r = analyze_ransomware(events)
        assert "critical" in r.severity_counts

    def test_agents_involved(self):
        events = [
            mk_event(action="encrypt files on disk", agent_id="a1"),
            mk_event(action="create ransom note", agent_id="a2"),
        ]
        r = analyze_ransomware(events)
        assert "a1" in r.agents_involved
        assert "a2" in r.agents_involved

    def test_benign_events_not_counted(self):
        events = [mk_event(action="user logged in")]
        r = analyze_ransomware(events)
        assert r.violation_events == 0


class TestFormatText:
    def test_header(self):
        r = analyze_ransomware([])
        text = format_text(r)
        assert "Ransomware Behavior Detection" in text

    def test_contains_counts(self):
        events = [mk_event(action="encrypt files on disk")]
        r = analyze_ransomware(events)
        text = format_text(r)
        assert "Total events" in text

    def test_contains_categories(self):
        events = [mk_event(action="encrypt files on disk")]
        r = analyze_ransomware(events)
        text = format_text(r)
        assert "file_encryption" in text


class TestFormatJSON:
    def test_valid_json(self):
        events = [mk_event(action="encrypt files on disk")]
        r = analyze_ransomware(events)
        out = format_json(r)
        data = json.loads(out)
        assert "total_events" in data
        assert "categories" in data

    def test_empty_valid(self):
        r = analyze_ransomware([])
        data = json.loads(format_json(r))
        assert data["total_events"] == 0

    def test_chains_in_json(self):
        events = [mk_event(action="encrypt files on disk")]
        r = analyze_ransomware(events)
        data = json.loads(format_json(r))
        assert "chains" in data


class TestLoadEvents:
    def test_nonexistent_file(self):
        events = _load_events("/nonexistent/path.json")
        assert events == []

    def test_load_list(self, tmp_path):
        f = tmp_path / "events.json"
        f.write_text(json.dumps([{"action": "test"}]))
        events = _load_events(str(f))
        assert len(events) == 1

    def test_load_dict_with_events(self, tmp_path):
        f = tmp_path / "events.json"
        f.write_text(json.dumps({"events": [{"action": "test"}]}))
        events = _load_events(str(f))
        assert len(events) == 1

    def test_load_single_dict(self, tmp_path):
        f = tmp_path / "event.json"
        f.write_text(json.dumps({"action": "test"}))
        events = _load_events(str(f))
        assert len(events) == 1
