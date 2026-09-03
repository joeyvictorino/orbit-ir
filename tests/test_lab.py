from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from orbit_ir.analyzer import EvidenceFormatError, analyze_dataset
from orbit_ir.generator import LabConfig, generate_dataset


class LabTest(unittest.TestCase):
    def test_reconstructs_generated_incident(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=40,
                messages=500,
                transcripts=80,
                participants=24,
                spoofed_tool_calls=7,
                coordinators=3,
                seed=17,
            )
            truth = generate_dataset(root / "evidence", config)
            summary = analyze_dataset(
                root / "evidence",
                root / "results",
                ground_truth_path=root / "evidence" / "ground_truth.json",
            )

            self.assertTrue(summary["synthetic"])
            self.assertEqual(summary["corpus"]["messages"], 500)
            self.assertEqual(summary["findings"]["transcript_tool_call_mismatches"], 7)
            self.assertEqual(summary["evaluation"]["spoof_detection"]["false_positive"], 0)
            self.assertEqual(summary["evaluation"]["spoof_detection"]["false_negative"], 0)
            self.assertEqual(set(summary["findings"]["top_coordinators"]), set(truth["coordinators"]))
            self.assertTrue((root / "results" / "evidence_manifest.json").exists())
            self.assertTrue((root / "results" / "findings.csv").exists())

            with (root / "results" / "findings.csv").open(newline="", encoding="utf-8") as stream:
                first_finding = next(csv.DictReader(stream))
            self.assertTrue(first_finding["transcript_line"].isdigit())
            self.assertTrue(first_finding["control_line"].isdigit())
            self.assertEqual(first_finding["transcript_source"], "transcripts.jsonl")
            self.assertEqual(first_finding["control_source"], "control_plane.jsonl")

    def test_generation_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(agents=20, messages=100, transcripts=30, participants=12, spoofed_tool_calls=3, coordinators=2, seed=9)
            generate_dataset(root / "one", config)
            generate_dataset(root / "two", config)
            for filename in ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl", "ground_truth.json"):
                self.assertEqual((root / "one" / filename).read_bytes(), (root / "two" / filename).read_bytes())

    def test_analysis_does_not_require_ground_truth(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generate_dataset(
                root / "evidence",
                LabConfig(agents=20, messages=100, transcripts=30, participants=12, spoofed_tool_calls=3, coordinators=2, seed=9),
            )
            (root / "evidence" / "ground_truth.json").unlink()
            summary = analyze_dataset(root / "evidence", root / "results")
            self.assertNotIn("evaluation", summary)
            self.assertEqual(summary["findings"]["transcript_tool_call_mismatches"], 3)
            self.assertEqual(summary["method"]["ground_truth_dependency"], "none; an optional fixture is used only after detections for evaluation")

    def test_missing_transcript_is_reported_with_source_line(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generate_dataset(
                root / "evidence",
                LabConfig(agents=20, messages=100, transcripts=30, participants=12, spoofed_tool_calls=0, coordinators=2, seed=9),
            )
            transcript_path = root / "evidence" / "transcripts.jsonl"
            rows = transcript_path.read_text(encoding="utf-8").splitlines()
            transcript_path.write_text("\n".join(rows[1:]) + "\n", encoding="utf-8")

            summary = analyze_dataset(root / "evidence", root / "results")
            self.assertEqual(summary["findings"]["missing_transcripts"], 1)
            with (root / "results" / "findings.csv").open(newline="", encoding="utf-8") as stream:
                findings = list(csv.DictReader(stream))
            missing = next(item for item in findings if item["reasons"] == "missing-transcript")
            self.assertEqual(missing["control_line"], "1")
            self.assertEqual(missing["transcript_line"], "")

    def test_identity_and_trace_swaps_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generate_dataset(
                root / "evidence",
                LabConfig(agents=20, messages=100, transcripts=30, participants=12, spoofed_tool_calls=0, coordinators=2, seed=9),
            )
            control_path = root / "evidence" / "control_plane.jsonl"
            controls = [json.loads(row) for row in control_path.read_text(encoding="utf-8").splitlines()]
            controls[0]["agent_id"] = "agent-attacker"
            controls[0]["trace_id"] = "trace-attacker"
            control_path.write_text(
                "\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in controls) + "\n",
                encoding="utf-8",
            )

            summary = analyze_dataset(root / "evidence", root / "results")
            self.assertEqual(summary["findings"]["identity_or_trace_conflicts"], 2)
            text = (root / "results" / "findings.csv").read_text(encoding="utf-8")
            self.assertIn("agent-id-mismatch;trace-id-mismatch", text)

    def test_duplicate_tool_call_ids_are_not_silently_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generate_dataset(
                root / "evidence",
                LabConfig(agents=20, messages=100, transcripts=30, participants=12, spoofed_tool_calls=0, coordinators=2, seed=9),
            )
            transcript_path = root / "evidence" / "transcripts.jsonl"
            rows = transcript_path.read_text(encoding="utf-8").splitlines()
            transcript_path.write_text("\n".join(rows + [rows[0]]) + "\n", encoding="utf-8")

            summary = analyze_dataset(root / "evidence", root / "results")
            self.assertEqual(summary["findings"]["duplicate_tool_call_identifiers"], 1)
            text = (root / "results" / "findings.csv").read_text(encoding="utf-8")
            self.assertIn("duplicate-transcript-tool-call-id", text)
            self.assertIn("1;31", text)

    def test_malformed_json_reports_the_exact_source_line(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generate_dataset(
                root / "evidence",
                LabConfig(agents=20, messages=100, transcripts=30, participants=12, spoofed_tool_calls=0, coordinators=2, seed=9),
            )
            message_path = root / "evidence" / "messages.jsonl"
            rows = message_path.read_text(encoding="utf-8").splitlines()
            message_path.write_text("{not-json}\n" + "\n".join(rows[1:]) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(EvidenceFormatError, r"messages\.jsonl:1: invalid JSON"):
                analyze_dataset(root / "evidence", root / "results")

    def test_generator_rejects_unsafe_zero_participant_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "participants must be at least 1"):
                generate_dataset(
                    Path(temp) / "evidence",
                    LabConfig(agents=20, messages=100, transcripts=30, participants=0, spoofed_tool_calls=0, coordinators=0, seed=9),
                )


if __name__ == "__main__":
    unittest.main()
