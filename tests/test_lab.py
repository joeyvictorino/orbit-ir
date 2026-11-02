from __future__ import annotations

import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from orbit_ir import cli
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
                unbacked_completions=5,
                oracle_modifications=3,
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

            self.assertEqual(summary["findings"]["unbacked_completions"], 5)
            self.assertEqual(summary["findings"]["oracle_integrity_violations"], 3)
            self.assertEqual(summary["evaluation"]["unbacked_completion_detection"]["false_positive"], 0)
            self.assertEqual(summary["evaluation"]["unbacked_completion_detection"]["false_negative"], 0)
            self.assertEqual(summary["evaluation"]["oracle_modification_detection"]["false_positive"], 0)
            self.assertEqual(summary["evaluation"]["oracle_modification_detection"]["false_negative"], 0)

    def test_generation_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(agents=20, messages=100, transcripts=30, participants=12, spoofed_tool_calls=3, coordinators=2, unbacked_completions=0, oracle_modifications=0, seed=9)
            generate_dataset(root / "one", config)
            generate_dataset(root / "two", config)
            for filename in ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl", "ground_truth.json"):
                self.assertEqual((root / "one" / filename).read_bytes(), (root / "two" / filename).read_bytes())

    def test_analysis_does_not_require_ground_truth(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generate_dataset(
                root / "evidence",
                LabConfig(agents=20, messages=100, transcripts=30, participants=12, spoofed_tool_calls=3, coordinators=2, unbacked_completions=0, oracle_modifications=0, seed=9),
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
                LabConfig(agents=20, messages=100, transcripts=30, participants=12, spoofed_tool_calls=0, coordinators=2, unbacked_completions=0, oracle_modifications=0, seed=9),
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
                LabConfig(agents=20, messages=100, transcripts=30, participants=12, spoofed_tool_calls=0, coordinators=2, unbacked_completions=0, oracle_modifications=0, seed=9),
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
                LabConfig(agents=20, messages=100, transcripts=30, participants=12, spoofed_tool_calls=0, coordinators=2, unbacked_completions=0, oracle_modifications=0, seed=9),
            )
            transcript_path = root / "evidence" / "transcripts.jsonl"
            rows = transcript_path.read_text(encoding="utf-8").splitlines()
            transcript_path.write_text("\n".join(rows + [rows[0]]) + "\n", encoding="utf-8")

            summary = analyze_dataset(root / "evidence", root / "results")
            self.assertEqual(summary["findings"]["duplicate_tool_call_identifiers"], 1)
            text = (root / "results" / "findings.csv").read_text(encoding="utf-8")
            self.assertIn("duplicate-transcript-tool-call-id", text)
            self.assertIn("1;31", text)

    def test_unbacked_completions_detected_without_tool_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=20, messages=100, transcripts=30, participants=12,
                spoofed_tool_calls=0, coordinators=2,
                unbacked_completions=4, oracle_modifications=0, seed=42,
            )
            generate_dataset(root / "evidence", config)
            summary = analyze_dataset(
                root / "evidence", root / "results",
                ground_truth_path=root / "evidence" / "ground_truth.json",
            )
            self.assertEqual(summary["findings"]["unbacked_completions"], 4)
            self.assertEqual(summary["findings"]["transcript_tool_call_mismatches"], 0)
            self.assertEqual(summary["evaluation"]["unbacked_completion_detection"]["true_positive"], 4)
            self.assertEqual(summary["evaluation"]["unbacked_completion_detection"]["false_positive"], 0)
            text = (root / "results" / "findings.csv").read_text(encoding="utf-8")
            self.assertIn("unbacked-completion", text)
            self.assertNotIn("tool-name-mismatch", text)

    def test_oracle_modifications_detected_by_resource_and_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=20, messages=100, transcripts=30, participants=12,
                spoofed_tool_calls=0, coordinators=2,
                unbacked_completions=0, oracle_modifications=3, seed=42,
            )
            generate_dataset(root / "evidence", config)
            summary = analyze_dataset(
                root / "evidence", root / "results",
                ground_truth_path=root / "evidence" / "ground_truth.json",
            )
            self.assertEqual(summary["findings"]["oracle_integrity_violations"], 3)
            self.assertEqual(summary["findings"]["transcript_tool_call_mismatches"], 0)
            self.assertEqual(summary["evaluation"]["oracle_modification_detection"]["true_positive"], 3)
            self.assertEqual(summary["evaluation"]["oracle_modification_detection"]["false_positive"], 0)
            text = (root / "results" / "findings.csv").read_text(encoding="utf-8")
            self.assertIn("oracle-integrity-violation", text)

    def test_credential_reuse_detected_across_agents(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=20, messages=100, transcripts=60, participants=12,
                spoofed_tool_calls=0, coordinators=2,
                unbacked_completions=0, oracle_modifications=0, seed=9,
            )
            generate_dataset(root / "evidence", config)
            summary = analyze_dataset(root / "evidence", root / "results")
            self.assertGreater(summary["findings"]["shared_credentials"], 0)
            reuse = json.loads((root / "results" / "credential_reuse.json").read_text(encoding="utf-8"))
            self.assertIsInstance(reuse, list)
            self.assertGreater(len(reuse), 0)
            first = reuse[0]
            self.assertIn("credential_id", first)
            self.assertIn("agents", first)
            self.assertGreater(first["agent_count"], 1)

    def test_mitre_techniques_mapped_to_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=40, messages=500, transcripts=80, participants=24,
                spoofed_tool_calls=7, coordinators=3,
                unbacked_completions=5, oracle_modifications=3, seed=17,
            )
            generate_dataset(root / "evidence", config)
            summary = analyze_dataset(
                root / "evidence", root / "results",
                ground_truth_path=root / "evidence" / "ground_truth.json",
            )
            mitre_counts = summary["findings"]["mitre_technique_counts"]
            self.assertIn("T1036 Masquerading", mitre_counts)
            self.assertIn("T1565 Data Manipulation", mitre_counts)
            self.assertEqual(mitre_counts["T1565 Data Manipulation"], 3)

            with (root / "results" / "findings.csv").open(newline="", encoding="utf-8") as stream:
                reader = csv.DictReader(stream)
                rows = list(reader)
            self.assertIn("mitre_techniques", reader.fieldnames)
            spoof_row = next(r for r in rows if "tool-name-mismatch" in r["reasons"])
            self.assertIn("T1036:Masquerading", spoof_row["mitre_techniques"])
            oracle_row = next(r for r in rows if "oracle-integrity-violation" in r["reasons"])
            self.assertIn("T1565:Data Manipulation", oracle_row["mitre_techniques"])

            report_text = (root / "results" / "report.md").read_text(encoding="utf-8")
            self.assertIn("## MITRE ATT&CK mapping", report_text)
            self.assertIn("T1036", report_text)
            self.assertIn("T1565", report_text)
            self.assertIn("Masquerading", report_text)

    def test_timeline_appears_in_report_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=40, messages=500, transcripts=80, participants=24,
                spoofed_tool_calls=7, coordinators=3,
                unbacked_completions=5, oracle_modifications=3, seed=17,
            )
            generate_dataset(root / "evidence", config)
            summary = analyze_dataset(
                root / "evidence", root / "results",
                ground_truth_path=root / "evidence" / "ground_truth.json",
            )
            self.assertGreater(summary["findings"]["timeline_events"], 0)
            self.assertGreater(summary["findings"]["timeline_finding_events"], 0)
            self.assertGreater(summary["findings"]["timeline_assignment_events"], 0)

            timeline = json.loads((root / "results" / "timeline.json").read_text(encoding="utf-8"))
            self.assertIsInstance(timeline, list)
            self.assertGreater(len(timeline), 0)
            timestamps = [e["timestamp"] for e in timeline]
            self.assertEqual(timestamps, sorted(timestamps))
            event_types = {e["event_type"] for e in timeline}
            self.assertIn("finding", event_types)
            self.assertIn("coordinator-assignment", event_types)
            for event in timeline:
                self.assertIn("timestamp", event)
                self.assertIn("agent_id", event)
                self.assertIn("source", event)
                self.assertIn("event_type", event)
                self.assertIn("detail", event)

            report_text = (root / "results" / "report.md").read_text(encoding="utf-8")
            self.assertIn("## Timeline", report_text)
            self.assertIn("### Finding-linked events", report_text)
            self.assertIn("### Coordinator assignments", report_text)
            self.assertIn("### Activity by hour", report_text)
            self.assertIn("timeline.json", report_text)

    def test_data_quality_section_in_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=20, messages=100, transcripts=30, participants=12,
                spoofed_tool_calls=0, coordinators=2,
                unbacked_completions=0, oracle_modifications=0, seed=9,
            )
            generate_dataset(root / "evidence", config)
            transcript_path = root / "evidence" / "transcripts.jsonl"
            rows = transcript_path.read_text(encoding="utf-8").splitlines()
            transcript_path.write_text("\n".join(rows[1:]) + "\n", encoding="utf-8")

            summary = analyze_dataset(root / "evidence", root / "results")
            dq = json.loads((root / "results" / "data_quality.json").read_text(encoding="utf-8"))
            self.assertIn("missing_transcript_ids", dq)
            self.assertIn("missing_control_plane_ids", dq)
            self.assertIn("duplicate_transcript_tool_call_ids", dq)
            self.assertIn("duplicate_control_tool_call_ids", dq)
            self.assertEqual(len(dq["missing_transcript_ids"]), 1)

            report_text = (root / "results" / "report.md").read_text(encoding="utf-8")
            self.assertIn("## Data quality", report_text)
            self.assertIn("Missing transcript records", report_text)
            self.assertIn("data_quality.json", report_text)

    def test_data_quality_clean_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=20, messages=100, transcripts=30, participants=12,
                spoofed_tool_calls=3, coordinators=2,
                unbacked_completions=0, oracle_modifications=0, seed=9,
            )
            generate_dataset(root / "evidence", config)
            analyze_dataset(root / "evidence", root / "results")
            report_text = (root / "results" / "report.md").read_text(encoding="utf-8")
            self.assertIn("## Data quality", report_text)
            self.assertIn("No duplicate IDs, missing records, or duplicate tool-call IDs detected", report_text)

    def test_mitre_deduplication_per_finding(self) -> None:
        from orbit_ir.analyzer import _mitre_for_reasons
        techniques = _mitre_for_reasons(["tool-name-mismatch", "argument-digest-mismatch"])
        ids = [t["id"] for t in techniques]
        self.assertEqual(ids, ["T1036"])

    def test_malformed_json_reports_the_exact_source_line(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generate_dataset(
                root / "evidence",
                LabConfig(agents=20, messages=100, transcripts=30, participants=12, spoofed_tool_calls=0, coordinators=2, unbacked_completions=0, oracle_modifications=0, seed=9),
            )
            message_path = root / "evidence" / "messages.jsonl"
            rows = message_path.read_text(encoding="utf-8").splitlines()
            message_path.write_text("{not-json}\n" + "\n".join(rows[1:]) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(EvidenceFormatError, r"messages\.jsonl:1: invalid JSON"):
                analyze_dataset(root / "evidence", root / "results")

    def test_generator_rejects_unsafe_zero_participant_configuration(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp,
            self.assertRaisesRegex(ValueError, "participants must be at least 1"),
        ):
            generate_dataset(
                Path(temp) / "evidence",
                LabConfig(agents=20, messages=100, transcripts=30, participants=0, spoofed_tool_calls=0, coordinators=0, seed=9),
            )

    def test_cli_reports_malformed_evidence_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            generate_dataset(root / "evidence", LabConfig(agents=20, messages=100, transcripts=30, participants=10, spoofed_tool_calls=3, coordinators=2, unbacked_completions=0, oracle_modifications=0, seed=5))
            message_path = root / "evidence" / "messages.jsonl"
            rows = message_path.read_text(encoding="utf-8").splitlines()
            message_path.write_text("{not-json}\n" + "\n".join(rows[1:]) + "\n", encoding="utf-8")
            argv = ["orbit-ir", "analyze", "--input", str(root / "evidence"), "--out", str(root / "results")]
            stderr = io.StringIO()
            with (
                mock.patch("sys.argv", argv),
                contextlib.redirect_stderr(stderr),
                self.assertRaises(SystemExit) as raised,
            ):
                cli.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("error: messages.jsonl:1: invalid JSON", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_reports_missing_evidence_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            argv = ["orbit-ir", "analyze", "--input", str(Path(temp) / "nope"), "--out", str(Path(temp) / "out")]
            stderr = io.StringIO()
            with (
                mock.patch("sys.argv", argv),
                contextlib.redirect_stderr(stderr),
                self.assertRaises(SystemExit) as raised,
            ):
                cli.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("missing evidence source", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
