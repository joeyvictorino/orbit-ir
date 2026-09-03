from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from orbit_ir.analyzer import analyze_dataset
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
            summary = analyze_dataset(root / "evidence", root / "results")

            self.assertTrue(summary["synthetic"])
            self.assertEqual(summary["corpus"]["messages"], 500)
            self.assertEqual(summary["findings"]["transcript_tool_call_mismatches"], 7)
            self.assertEqual(summary["evaluation"]["spoof_detection"]["false_positive"], 0)
            self.assertEqual(summary["evaluation"]["spoof_detection"]["false_negative"], 0)
            self.assertEqual(set(summary["findings"]["top_coordinators"]), set(truth["coordinators"]))
            self.assertTrue((root / "results" / "evidence_manifest.json").exists())
            self.assertTrue((root / "results" / "findings.csv").exists())

    def test_generation_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(agents=20, messages=100, transcripts=30, participants=12, spoofed_tool_calls=3, coordinators=2, seed=9)
            generate_dataset(root / "one", config)
            generate_dataset(root / "two", config)
            for filename in ("messages.jsonl", "transcripts.jsonl", "control_plane.jsonl", "ground_truth.json"):
                self.assertEqual((root / "one" / filename).read_bytes(), (root / "two" / filename).read_bytes())


if __name__ == "__main__":
    unittest.main()
