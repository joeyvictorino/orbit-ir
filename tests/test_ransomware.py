import json
import os
import tempfile
import pytest
from orbit_ir.ransomware import classify_event, analyze, format_report, load_events, CATEGORIES


class TestClassifyEvent:
    def test_file_encryption(self):
        assert classify_event("mass encryption of user files detected") == "file_encryption"

    def test_crypto_locker(self):
        assert classify_event("crypto locker process started") == "file_encryption"

    def test_ransomware_encryption(self):
        assert classify_event("ransomware encryption routine active") == "file_encryption"

    def test_ransom_note(self):
        assert classify_event("ransom note dropped in directories") == "ransom_note"

    def test_bitcoin_payment(self):
        assert classify_event("bitcoin payment demanded for decryption") == "ransom_note"

    def test_decryption_key_demand(self):
        assert classify_event("decryption key demand sent to victim") == "ransom_note"

    def test_shadow_copy_deletion(self):
        assert classify_event("shadow copy deletion via vssadmin") == "shadow_copy"

    def test_vssadmin_delete(self):
        assert classify_event("vssadmin delete shadows /all") == "shadow_copy"

    def test_backup_deletion(self):
        assert classify_event("backup deletion across all drives") == "shadow_copy"

    def test_ransomware_propagation(self):
        assert classify_event("ransomware propagation to adjacent hosts") == "lateral_spread"

    def test_smb_propagation(self):
        assert classify_event("smb propagation of malware payload") == "lateral_spread"

    def test_network_share_encryption(self):
        assert classify_event("network share encryption started") == "lateral_spread"

    def test_antivirus_disabled(self):
        assert classify_event("antivirus disabled by malicious process") == "defense_evasion"

    def test_defender_disabled(self):
        assert classify_event("defender disabled via group policy") == "defense_evasion"

    def test_edr_bypass(self):
        assert classify_event("edr bypass technique observed") == "defense_evasion"

    def test_double_extortion(self):
        assert classify_event("double extortion campaign launched") == "exfil_before_encrypt"

    def test_data_theft_before_encryption(self):
        assert classify_event("data theft before encryption phase") == "exfil_before_encrypt"

    def test_leak_site_upload(self):
        assert classify_event("leak site upload of stolen data") == "exfil_before_encrypt"

    def test_unknown(self):
        assert classify_event("normal file access operation") == "unknown"

    def test_none_event(self):
        assert classify_event(None) == "unknown"

    def test_empty_string(self):
        assert classify_event("") == "unknown"

    def test_whitespace_only(self):
        assert classify_event("   ") == "unknown"

    def test_dict_event(self):
        assert classify_event({"action": "mass encryption detected"}) == "file_encryption"

    def test_case_insensitive(self):
        assert classify_event("RANSOM NOTE Dropped") == "ransom_note"

    def test_non_string_non_dict(self):
        assert classify_event(42) == "unknown"


class TestAnalyze:
    def test_empty(self):
        result = analyze([])
        assert result["total_events"] == 0
        assert result["flagged_count"] == 0
        assert result["severity"] == "none"

    def test_single_match(self):
        result = analyze(["file encryption detected"])
        assert result["flagged_count"] == 1
        assert result["severity"] == "medium"

    def test_no_matches(self):
        result = analyze(["normal file access", "standard backup operation"])
        assert result["flagged_count"] == 0

    def test_severity_high(self):
        events = [f"file encryption event {i}" for i in range(6)]
        result = analyze(events)
        assert result["severity"] == "high"

    def test_severity_critical(self):
        events = [f"file encryption event {i}" for i in range(11)]
        result = analyze(events)
        assert result["severity"] == "critical"

    def test_category_counts(self):
        events = ["file encryption started", "ransom note found", "file encryption again"]
        result = analyze(events)
        assert result["category_counts"]["file_encryption"] == 2
        assert result["category_counts"]["ransom_note"] == 1

    def test_detection_rate(self):
        result = analyze(["file encryption", "normal", "ransom note", "safe"])
        assert result["detection_rate"] == 0.5

    def test_flagged_structure(self):
        result = analyze(["ransomware encryption active"])
        entry = result["flagged_events"][0]
        assert entry["index"] == 0
        assert entry["category"] == "file_encryption"
        assert entry["event"] == "ransomware encryption active"


class TestFormatReport:
    def test_format_empty(self):
        result = analyze([])
        text = format_report(result)
        assert "Ransomware" in text

    def test_format_with_findings(self):
        result = analyze(["ransom note dropped"])
        text = format_report(result)
        assert "ransom_note" in text

    def test_format_truncation(self):
        events = [f"file encryption event {i}" for i in range(15)]
        result = analyze(events)
        text = format_report(result)
        assert "... and 5 more" in text

    def test_format_detection_rate(self):
        result = analyze(["file encryption", "normal"])
        text = format_report(result)
        assert "50.0%" in text


class TestLoadEvents:
    def test_load_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["event1", "event2"], f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_dict_with_events_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"events": ["a", "b"]}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 2

    def test_load_single_dict(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"action": "test"}, f)
            f.flush()
            events = load_events(f.name)
        os.unlink(f.name)
        assert len(events) == 1


class TestCategories:
    def test_all_categories_have_patterns(self):
        for cat, patterns in CATEGORIES.items():
            assert len(patterns) > 0, f"category {cat} has no patterns"

    def test_category_names(self):
        expected = {"file_encryption", "ransom_note", "shadow_copy", "lateral_spread", "defense_evasion", "exfil_before_encrypt"}
        assert set(CATEGORIES.keys()) == expected
