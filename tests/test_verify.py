from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from orbit_ir.analyzer import verify_evidence, _sha256
from orbit_ir.generator import LabConfig, generate_dataset


class VerifyTest(unittest.TestCase):
    def _generate(self, root: Path) -> tuple[Path, Path]:
        data_dir = root / "evidence"
        result_dir = root / "results"
        generate_dataset(data_dir, LabConfig(
            agents=10, messages=50, transcripts=20,
            participants=8, spoofed_tool_calls=2,
            coordinators=2, unbacked_completions=2,
            oracle_modifications=1, lateral_accesses=1,
            seed=42,
        ))
        from orbit_ir.analyzer import analyze_dataset
        analyze_dataset(data_dir, result_dir, ground_truth_path=data_dir / "ground_truth.json")
        return data_dir, result_dir

    def test_verify_valid_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir, result_dir = self._generate(root)
            manifest_path = result_dir / "evidence_manifest.json"
            result = verify_evidence(data_dir, manifest_path=manifest_path)
            for f in result["files"]:
                self.assertEqual(f["status"], "ok", f"{f['name']}: {f['detail']}")

    def test_verify_detects_modification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir, result_dir = self._generate(root)
            manifest_path = result_dir / "evidence_manifest.json"
            msg_path = data_dir / "messages.jsonl"
            msg_path.write_text("tampered\n", encoding="utf-8")
            result = verify_evidence(data_dir, manifest_path=manifest_path)
            statuses = {f["name"]: f["status"] for f in result["files"]}
            self.assertEqual(statuses["messages.jsonl"], "mismatch")

    def test_verify_detects_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir, result_dir = self._generate(root)
            manifest_path = result_dir / "evidence_manifest.json"
            (data_dir / "control_plane.jsonl").unlink()
            result = verify_evidence(data_dir, manifest_path=manifest_path)
            statuses = {f["name"]: f["status"] for f in result["files"]}
            self.assertEqual(statuses["control_plane.jsonl"], "missing")

    def test_verify_without_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "evidence"
            data_dir.mkdir(parents=True)
            for name in ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl"):
                (data_dir / name).write_text("{}\n", encoding="utf-8")
            result = verify_evidence(data_dir)
            self.assertEqual(len(result["files"]), 3)
            for f in result["files"]:
                self.assertEqual(f["status"], "ok")
                self.assertIn("no manifest", f["detail"])

    def test_cli_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir, result_dir = self._generate(root)
            import io
            import contextlib
            from orbit_ir import cli
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli._run(cli.build_parser().parse_args([
                    "verify", "--input", str(data_dir),
                    "--manifest", str(result_dir / "evidence_manifest.json"),
                ]))
            output = out.getvalue()
            self.assertIn("OK", output)
            self.assertIn("verified", output)


if __name__ == "__main__":
    unittest.main()
