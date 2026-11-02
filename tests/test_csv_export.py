from __future__ import annotations

import csv
import io
import json
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from orbit_ir import cli
from orbit_ir.analyzer import analyze_dataset
from orbit_ir.generator import LabConfig, generate_dataset


def _make_dataset(root: Path) -> tuple[Path, Path]:
    config = LabConfig(
        agents=40, messages=500, transcripts=80, participants=24,
        spoofed_tool_calls=7, coordinators=3, unbacked_completions=5,
        oracle_modifications=3, seed=42,
    )
    evidence_dir = root / "evidence"
    generate_dataset(evidence_dir, config)
    results_dir = root / "results"
    return evidence_dir, results_dir


class TestCSVFileWritten(TestCase):
    def test_findings_csv_exists_after_analyze(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence_dir, results_dir = _make_dataset(root)
            analyze_dataset(evidence_dir, results_dir)
            csv_path = results_dir / "findings.csv"
            self.assertTrue(csv_path.exists(), "findings.csv should be written by analyze")

    def test_findings_csv_has_header_and_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence_dir, results_dir = _make_dataset(root)
            analyze_dataset(evidence_dir, results_dir)
            csv_path = results_dir / "findings.csv"
            with csv_path.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            self.assertGreater(len(rows), 0, "CSV should have findings")
            self.assertIn("finding_id", reader.fieldnames)
            self.assertIn("confidence", reader.fieldnames)
            self.assertIn("claimed_tool", reader.fieldnames)

    def test_findings_csv_row_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence_dir, results_dir = _make_dataset(root)
            analyze_dataset(evidence_dir, results_dir)
            csv_path = results_dir / "findings.csv"
            with csv_path.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                row = next(reader)
            self.assertIn("finding_id", row)
            self.assertIn("tool_call_id", row)
            self.assertIn("reasons", row)
            self.assertTrue(row["finding_id"], "finding_id should not be empty")


class TestCSVFormatFlag(TestCase):
    def test_format_csv_prints_csv_to_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence_dir, results_dir = _make_dataset(root)

            with mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
                old_argv = sys.argv
                sys.argv = [
                    "orbit-ir", "analyze",
                    "--input", str(evidence_dir),
                    "--out", str(results_dir),
                    "--format", "csv",
                ]
                try:
                    cli._run(cli.build_parser().parse_args())
                finally:
                    sys.argv = old_argv

            output = stdout.getvalue()
            self.assertIn("finding_id", output, "CSV header should be in stdout")
            reader = csv.DictReader(io.StringIO(output))
            rows = list(reader)
            self.assertGreater(len(rows), 0)

    def test_format_csv_matches_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence_dir, results_dir = _make_dataset(root)

            with mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
                old_argv = sys.argv
                sys.argv = [
                    "orbit-ir", "analyze",
                    "--input", str(evidence_dir),
                    "--out", str(results_dir),
                    "--format", "csv",
                ]
                try:
                    cli._run(cli.build_parser().parse_args())
                finally:
                    sys.argv = old_argv

            stdout_text = stdout.getvalue()
            file_text = (results_dir / "findings.csv").read_text(encoding="utf-8")
            self.assertEqual(stdout_text, file_text)
