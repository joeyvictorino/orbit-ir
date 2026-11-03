"""Tests for kill chain completeness scoring."""
import json
import tempfile
from pathlib import Path

import pytest

from orbit_ir.kill_chain import (
    analyze_kill_chain,
    format_kill_chain_text,
    load_and_analyze,
    _extract_techniques,
    _find_chain_segments,
    _grade,
    PhaseResult,
    KILL_CHAIN_PHASES,
)


def test_empty_events():
    report = analyze_kill_chain([])
    assert report.phases_covered == 0
    assert report.overall_score == 0
    assert report.grade == "F"
    assert len(report.gaps) == len(KILL_CHAIN_PHASES)


def test_single_technique():
    events = [{"mitre_technique": "T1190", "action": "exploit"}]
    report = analyze_kill_chain(events)
    assert report.phases_covered >= 1
    phase = next(p for p in report.phases if p.phase == "Initial Access")
    assert phase.covered
    assert "T1190" in phase.techniques_observed


def test_multiple_phases():
    events = [
        {"mitre_technique": "T1190"},  # Initial Access
        {"mitre_technique": "T1059"},  # Execution
        {"mitre_technique": "T1547"},  # Persistence
        {"mitre_technique": "T1548"},  # Privilege Escalation
    ]
    report = analyze_kill_chain(events)
    assert report.phases_covered >= 4
    assert report.longest_chain >= 4


def test_full_coverage():
    events = [
        {"mitre_technique": "T1190"},  # Initial Access
        {"mitre_technique": "T1059"},  # Execution
        {"mitre_technique": "T1547"},  # Persistence
        {"mitre_technique": "T1548"},  # Privilege Escalation
        {"mitre_technique": "T1036"},  # Defense Evasion
        {"mitre_technique": "T1110"},  # Credential Access
        {"mitre_technique": "T1046"},  # Discovery
        {"mitre_technique": "T1021"},  # Lateral Movement
        {"mitre_technique": "T1560"},  # Collection
        {"mitre_technique": "T1041"},  # Exfiltration
        {"mitre_technique": "T1071"},  # Command and Control
    ]
    report = analyze_kill_chain(events)
    assert report.phases_covered == 11
    assert report.overall_score > 0
    assert report.grade in ("A", "B", "C")
    assert len(report.gaps) == 0


def test_gap_detection():
    events = [
        {"mitre_technique": "T1190"},  # Initial Access
        {"mitre_technique": "T1547"},  # Persistence (skip Execution)
    ]
    report = analyze_kill_chain(events)
    gap_phases = {g.phase for g in report.gaps}
    assert "Execution" in gap_phases


def test_gap_severity_between_covered():
    events = [
        {"mitre_technique": "T1190"},  # Initial Access
        {"mitre_technique": "T1547"},  # Persistence (Execution is gap between covered phases)
    ]
    report = analyze_kill_chain(events)
    exec_gap = next((g for g in report.gaps if g.phase == "Execution"), None)
    assert exec_gap is not None
    assert exec_gap.severity in ("critical", "high")


def test_extract_techniques_various_fields():
    events = [
        {"mitre_technique": "T1190"},
        {"technique_id": "T1059"},
        {"technique": "T1547"},
        {"tags": ["T1548", "other"]},
        {"mitre_techniques": ["T1036", "T1070"]},
    ]
    techs = _extract_techniques(events)
    assert "T1190" in techs
    assert "T1059" in techs
    assert "T1547" in techs
    assert "T1548" in techs
    assert "T1036" in techs
    assert "T1070" in techs


def test_extract_techniques_empty():
    assert _extract_techniques([]) == set()


def test_chain_segments():
    phases = [
        PhaseResult(phase="A", covered=True),
        PhaseResult(phase="B", covered=True),
        PhaseResult(phase="C", covered=False),
        PhaseResult(phase="D", covered=True),
    ]
    longest, segments = _find_chain_segments(phases)
    assert longest == 2
    assert len(segments) == 2
    assert segments[0] == ["A", "B"]
    assert segments[1] == ["D"]


def test_chain_segments_all_covered():
    phases = [PhaseResult(phase=f"P{i}", covered=True) for i in range(5)]
    longest, segments = _find_chain_segments(phases)
    assert longest == 5
    assert len(segments) == 1


def test_chain_segments_none_covered():
    phases = [PhaseResult(phase=f"P{i}", covered=False) for i in range(3)]
    longest, segments = _find_chain_segments(phases)
    assert longest == 0
    assert len(segments) == 0


def test_grade():
    assert _grade(85) == "A"
    assert _grade(70) == "B"
    assert _grade(50) == "C"
    assert _grade(30) == "D"
    assert _grade(10) == "F"


def test_format_text():
    report = analyze_kill_chain([{"mitre_technique": "T1190"}])
    text = format_kill_chain_text(report)
    assert "Kill Chain Completeness" in text
    assert "Initial Access" in text
    assert "COVERED" in text
    assert "GAP" in text


def test_format_text_empty():
    report = analyze_kill_chain([])
    text = format_kill_chain_text(report)
    assert "Grade: F" in text


def test_load_and_analyze_file():
    events = [
        {"mitre_technique": "T1190"},
        {"mitre_technique": "T1059"},
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(events, f)
        f.flush()
        report = load_and_analyze(f.name)
    assert report.phases_covered >= 2


def test_load_and_analyze_directory():
    with tempfile.TemporaryDirectory() as d:
        p1 = Path(d) / "a.json"
        p1.write_text(json.dumps([{"mitre_technique": "T1190"}]))
        p2 = Path(d) / "b.json"
        p2.write_text(json.dumps([{"mitre_technique": "T1041"}]))
        report = load_and_analyze(d)
    assert report.phases_covered >= 2


def test_load_and_analyze_dict_format():
    data = {"events": [{"mitre_technique": "T1190"}]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.flush()
        report = load_and_analyze(f.name)
    assert report.phases_covered >= 1


def test_overall_score_increases_with_coverage():
    events_1 = [{"mitre_technique": "T1190"}]
    events_2 = [
        {"mitre_technique": "T1190"},
        {"mitre_technique": "T1059"},
        {"mitre_technique": "T1547"},
        {"mitre_technique": "T1041"},
    ]
    r1 = analyze_kill_chain(events_1)
    r2 = analyze_kill_chain(events_2)
    assert r2.overall_score > r1.overall_score


def test_missing_techniques_in_gaps():
    report = analyze_kill_chain([])
    for gap in report.gaps:
        assert len(gap.missing_techniques) > 0 or gap.phase not in [
            t["tactic"] for t in __import__("orbit_ir.mitre_report", fromlist=["TECHNIQUE_CATALOG"]).TECHNIQUE_CATALOG.values()
        ]
