"""Tests for ransomware detection module."""
import json
import os
import tempfile
import pytest
from orbit_ir.ransomware_detection import (
    CATEGORIES, ALL_INDICATORS, classify_event, analyze, format_report, load_events,
)


def test_categories_exist():
    assert len(CATEGORIES) == 6
    for cat, indicators in CATEGORIES.items():
        assert len(indicators) == 10


def test_all_indicators_count():
    assert len(ALL_INDICATORS) == 60


def test_classify_file_encryption():
    event = {"description": "Mass file rename with extension change detected"}
    matches = classify_event(event)
    assert any(m["category"] == "file_encryption" for m in matches)


def test_classify_ransom_note():
    event = {"description": "Ransom note file created in user directory"}
    matches = classify_event(event)
    assert any(m["category"] == "ransom_note" for m in matches)


def test_classify_lateral_spread():
    event = {"description": "SMB share enumeration detected on network"}
    matches = classify_event(event)
    assert any(m["category"] == "lateral_spread" for m in matches)


def test_classify_defense_evasion():
    event = {"description": "Antivirus service stopped by unknown process"}
    matches = classify_event(event)
    assert any(m["category"] == "defense_evasion" for m in matches)


def test_classify_exfiltration():
    event = {"description": "Large data archive created before encryption wave"}
    matches = classify_event(event)
    assert any(m["category"] == "exfiltration_threat" for m in matches)


def test_classify_persistence():
    event = {"description": "Scheduled task created for re-encryption attempt"}
    matches = classify_event(event)
    assert any(m["category"] == "persistence_mechanism" for m in matches)


def test_classify_no_match():
    event = {"description": "Normal user login at standard hours"}
    matches = classify_event(event)
    assert len(matches) == 0


def test_classify_uses_action_field():
    event = {"action": "mass file rename with extension change"}
    matches = classify_event(event)
    assert len(matches) > 0


def test_classify_uses_details_field():
    event = {"details": "ransomware ransom note file created"}
    matches = classify_event(event)
    assert len(matches) > 0


def test_analyze_empty():
    result = analyze([])
    assert result["severity"] == "none"
    assert result["total_indicators"] == 0


def test_analyze_single_event():
    events = [{"description": "Mass file rename with extension change on server"}]
    result = analyze(events)
    assert result["total_indicators"] >= 1
    assert result["severity"] in ("medium", "high", "critical")


def test_analyze_critical_severity():
    events = [
        {"description": "mass file rename with extension change"},
        {"description": "ransom note file created"},
        {"description": "smb share enumeration detected"},
        {"description": "antivirus service stopped"},
        {"description": "large data archive created before encryption"},
        {"description": "scheduled task created for re-encryption"},
        {"description": "shadow copy deletion attempt"},
        {"description": "event log cleared"},
        {"description": "database dump created"},
        {"description": "registry run key added for ransomware"},
        {"description": "bitcoin wallet address found in file"},
    ]
    result = analyze(events)
    assert result["severity"] == "critical"


def test_analyze_flagged_events():
    events = [
        {"description": "mass file rename with extension change"},
        {"description": "normal activity"},
    ]
    result = analyze(events)
    assert len(result["flagged_events"]) == 1


def test_analyze_category_counts():
    events = [{"description": "mass file rename with extension change"}]
    result = analyze(events)
    assert result["category_counts"]["file_encryption"] >= 1


def test_format_report_empty():
    result = analyze([])
    report = format_report(result)
    assert "Ransomware Detection" in report
    assert "none" in report


def test_format_report_with_findings():
    events = [{"description": "mass file rename with extension change"}]
    result = analyze(events)
    report = format_report(result)
    assert "file_encryption" in report


def test_format_report_severity():
    events = [{"description": "ransom note file created in directory"}]
    result = analyze(events)
    report = format_report(result)
    assert "Severity:" in report


def test_load_events(tmp_path):
    data = [{"description": "test event"}]
    p = tmp_path / "events.json"
    p.write_text(json.dumps(data))
    loaded = load_events(str(p))
    assert loaded == data


def test_detector_name():
    result = analyze([])
    assert result["detector"] == "ransomware_detection"


def test_multiple_categories_single_event():
    event = {"description": "mass file rename with extension change and shadow copy deletion attempt"}
    matches = classify_event(event)
    assert len(matches) >= 2


def test_case_insensitive():
    event = {"description": "MASS FILE RENAME WITH EXTENSION CHANGE"}
    matches = classify_event(event)
    assert len(matches) > 0
