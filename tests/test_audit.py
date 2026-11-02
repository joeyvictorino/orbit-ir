import json
import tempfile
from pathlib import Path

from orbit_ir.audit import audit_reproducibility, format_audit_text
from orbit_ir.generator import LabConfig, generate_dataset
from orbit_ir.analyzer import analyze_dataset


def test_audit_reproducible():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        evidence = tmp / "evidence"
        results1 = tmp / "results1"
        results2 = tmp / "results2"

        generate_dataset(evidence, LabConfig(seed=42, agents=10, messages=50,
                                              transcripts=100, participants=5,
                                              spoofed_tool_calls=2, coordinators=1))
        gt = evidence / "ground_truth.json"
        analyze_dataset(evidence, results1, ground_truth_path=gt)

        report = audit_reproducibility(evidence, results1, work_dir=results2)
        assert report["reproducible"] is True
        assert report["reference_hash"] == report["rerun_hash"]
        assert report["reference_count"] == report["rerun_count"]
        assert report["added_detection_types"] == []
        assert report["removed_detection_types"] == []


def test_audit_diverged():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        evidence = tmp / "evidence"
        ref = tmp / "reference"
        work = tmp / "work"

        generate_dataset(evidence, LabConfig(seed=42, agents=10, messages=50,
                                              transcripts=100, participants=5,
                                              spoofed_tool_calls=2, coordinators=1))
        ref.mkdir()
        (ref / "findings.json").write_text(json.dumps([
            {"detection_type": "fake", "severity": "high", "reasons": ["test"]}
        ]))

        report = audit_reproducibility(evidence, ref, work_dir=work)
        assert report["reproducible"] is False
        assert report["reference_count"] == 1


def test_format_audit_text_reproducible():
    result = {
        "reproducible": True,
        "reference_hash": "abc123def456",
        "rerun_hash": "abc123def456",
        "reference_count": 10,
        "rerun_count": 10,
        "added_detection_types": [],
        "removed_detection_types": [],
    }
    text = format_audit_text(result)
    assert "REPRODUCIBLE" in text
    assert "10 findings" in text


def test_format_audit_text_diverged():
    result = {
        "reproducible": False,
        "reference_hash": "aaa",
        "rerun_hash": "bbb",
        "reference_count": 10,
        "rerun_count": 12,
        "added_detection_types": ["new_type"],
        "removed_detection_types": [],
    }
    text = format_audit_text(result)
    assert "DIVERGED" in text
    assert "new_type" in text
