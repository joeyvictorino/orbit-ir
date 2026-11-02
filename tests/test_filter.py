from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from orbit_ir import cli
from orbit_ir.analyzer import analyze_dataset, filter_findings
from orbit_ir.generator import LabConfig, generate_dataset


class FilterFindingsTest(unittest.TestCase):
    def _make_findings(self) -> list[dict]:
        return [
            {
                "finding_id": "finding-000001",
                "tool_call_id": "tc-1",
                "agent_id_transcript": "agent-a",
                "agent_id_control": "agent-a",
                "reasons": ["tool-name-mismatch", "argument-digest-mismatch"],
                "confidence": "high",
                "confidence_score": 0.90,
            },
            {
                "finding_id": "finding-000002",
                "tool_call_id": "tc-2",
                "agent_id_transcript": "agent-b",
                "agent_id_control": "agent-b",
                "reasons": ["unbacked-completion"],
                "confidence": "medium",
                "confidence_score": 0.65,
            },
            {
                "finding_id": "finding-000003",
                "tool_call_id": "tc-3",
                "agent_id_transcript": "agent-c",
                "agent_id_control": "agent-c",
                "reasons": ["missing-transcript"],
                "confidence": "low",
                "confidence_score": 0.40,
            },
            {
                "finding_id": "finding-000004",
                "tool_call_id": "tc-4",
                "agent_id_transcript": "agent-a",
                "agent_id_control": "agent-d",
                "reasons": ["agent-id-mismatch"],
                "confidence": "medium",
                "confidence_score": 0.70,
            },
        ]

    def test_no_filters_returns_all(self) -> None:
        findings = self._make_findings()
        result = filter_findings(findings)
        self.assertEqual(len(result), 4)

    def test_min_confidence_high(self) -> None:
        findings = self._make_findings()
        result = filter_findings(findings, min_confidence="high")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["finding_id"], "finding-000001")

    def test_min_confidence_medium(self) -> None:
        findings = self._make_findings()
        result = filter_findings(findings, min_confidence="medium")
        self.assertEqual(len(result), 3)
        ids = {f["finding_id"] for f in result}
        self.assertEqual(ids, {"finding-000001", "finding-000002", "finding-000004"})

    def test_min_confidence_low_returns_all(self) -> None:
        findings = self._make_findings()
        result = filter_findings(findings, min_confidence="low")
        self.assertEqual(len(result), 4)

    def test_detection_type_single(self) -> None:
        findings = self._make_findings()
        result = filter_findings(findings, detection_types=["unbacked-completion"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["finding_id"], "finding-000002")

    def test_detection_type_multiple(self) -> None:
        findings = self._make_findings()
        result = filter_findings(
            findings,
            detection_types=["tool-name-mismatch", "missing-transcript"],
        )
        self.assertEqual(len(result), 2)
        ids = {f["finding_id"] for f in result}
        self.assertEqual(ids, {"finding-000001", "finding-000003"})

    def test_agent_filter(self) -> None:
        findings = self._make_findings()
        result = filter_findings(findings, agents=["agent-a"])
        self.assertEqual(len(result), 2)
        ids = {f["finding_id"] for f in result}
        self.assertEqual(ids, {"finding-000001", "finding-000004"})

    def test_agent_filter_matches_control_side(self) -> None:
        findings = self._make_findings()
        result = filter_findings(findings, agents=["agent-d"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["finding_id"], "finding-000004")

    def test_combined_filters(self) -> None:
        findings = self._make_findings()
        result = filter_findings(
            findings,
            min_confidence="medium",
            agents=["agent-a"],
        )
        self.assertEqual(len(result), 2)
        ids = {f["finding_id"] for f in result}
        self.assertEqual(ids, {"finding-000001", "finding-000004"})

    def test_combined_filters_narrow(self) -> None:
        findings = self._make_findings()
        result = filter_findings(
            findings,
            min_confidence="high",
            detection_types=["tool-name-mismatch"],
            agents=["agent-a"],
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["finding_id"], "finding-000001")

    def test_no_match_returns_empty(self) -> None:
        findings = self._make_findings()
        result = filter_findings(findings, agents=["agent-nonexistent"])
        self.assertEqual(len(result), 0)


class FilterCLIIntegrationTest(unittest.TestCase):
    def test_cli_min_confidence_filter(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=40, messages=500, transcripts=80, participants=24,
                spoofed_tool_calls=7, coordinators=3, unbacked_completions=5,
                oracle_modifications=3, seed=17,
            )
            evidence_dir = root / "evidence"
            generate_dataset(evidence_dir, config)
            results_dir = root / "results"

            args = cli.build_parser().parse_args([
                "analyze",
                "--input", str(evidence_dir),
                "--out", str(results_dir),
                "--min-confidence", "high",
            ])
            cli._run(args)

            summary = json.loads((results_dir / "summary.json").read_text())
            self.assertIn("filter", summary)
            self.assertEqual(summary["filter"]["min_confidence"], "high")
            self.assertGreaterEqual(
                summary["filter"]["total_before_filter"],
                summary["filter"]["total_after_filter"],
            )

            filtered_findings = json.loads((results_dir / "findings.json").read_text())
            for f in filtered_findings:
                self.assertEqual(f["confidence"], "high")

    def test_cli_detection_type_filter(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=40, messages=500, transcripts=80, participants=24,
                spoofed_tool_calls=7, coordinators=3, unbacked_completions=5,
                oracle_modifications=3, seed=17,
            )
            evidence_dir = root / "evidence"
            generate_dataset(evidence_dir, config)
            results_dir = root / "results"

            args = cli.build_parser().parse_args([
                "analyze",
                "--input", str(evidence_dir),
                "--out", str(results_dir),
                "--detection-type", "tool-name-mismatch,argument-digest-mismatch",
            ])
            cli._run(args)

            summary = json.loads((results_dir / "summary.json").read_text())
            self.assertEqual(
                summary["filter"]["detection_types"],
                ["tool-name-mismatch", "argument-digest-mismatch"],
            )
            filtered_findings = json.loads((results_dir / "findings.json").read_text())
            for f in filtered_findings:
                self.assertTrue(
                    {"tool-name-mismatch", "argument-digest-mismatch"} & set(f["reasons"]),
                    f"Finding {f['finding_id']} should have tool-name-mismatch or argument-digest-mismatch",
                )

    def test_cli_agent_filter(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=40, messages=500, transcripts=80, participants=24,
                spoofed_tool_calls=7, coordinators=3, unbacked_completions=5,
                oracle_modifications=3, seed=17,
            )
            evidence_dir = root / "evidence"
            generate_dataset(evidence_dir, config)
            results_dir = root / "results"

            unfiltered_args = cli.build_parser().parse_args([
                "analyze",
                "--input", str(evidence_dir),
                "--out", str(results_dir),
            ])
            cli._run(unfiltered_args)
            all_findings = json.loads((results_dir / "findings.json").read_text())
            if not all_findings:
                self.skipTest("no findings generated")

            target_agent = all_findings[0]["agent_id_transcript"] or all_findings[0]["agent_id_control"]
            if not target_agent:
                self.skipTest("no agent found in findings")

            results_dir2 = root / "results2"
            filtered_args = cli.build_parser().parse_args([
                "analyze",
                "--input", str(evidence_dir),
                "--out", str(results_dir2),
                "--agent", target_agent,
            ])
            cli._run(filtered_args)

            filtered = json.loads((results_dir2 / "findings.json").read_text())
            self.assertLessEqual(len(filtered), len(all_findings))
            for f in filtered:
                self.assertTrue(
                    f.get("agent_id_transcript") == target_agent
                    or f.get("agent_id_control") == target_agent,
                )

    def test_no_filter_no_filter_key_in_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=20, messages=100, transcripts=30, participants=12,
                spoofed_tool_calls=3, coordinators=2, unbacked_completions=0,
                oracle_modifications=0, seed=9,
            )
            evidence_dir = root / "evidence"
            generate_dataset(evidence_dir, config)
            results_dir = root / "results"

            args = cli.build_parser().parse_args([
                "analyze",
                "--input", str(evidence_dir),
                "--out", str(results_dir),
            ])
            cli._run(args)

            summary = json.loads((results_dir / "summary.json").read_text())
            self.assertNotIn("filter", summary)


if __name__ == "__main__":
    unittest.main()
