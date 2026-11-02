from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from orbit_ir import cli
from orbit_ir.analyzer import build_navigator_layer
from orbit_ir.generator import LabConfig, generate_dataset


class BuildNavigatorLayerTest(unittest.TestCase):
    def test_empty_findings(self) -> None:
        layer = build_navigator_layer([])
        self.assertEqual(layer["name"], "orbit-ir")
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertEqual(layer["techniques"], [])

    def test_single_finding(self) -> None:
        findings = [
            {
                "finding_id": "f-1",
                "reasons": ["tool-name-mismatch"],
                "severity": "critical",
            }
        ]
        layer = build_navigator_layer(findings)
        self.assertEqual(len(layer["techniques"]), 1)
        t = layer["techniques"][0]
        self.assertEqual(t["techniqueID"], "T1036")
        self.assertEqual(t["color"], "#ff0000")
        self.assertEqual(t["score"], 1)

    def test_multiple_findings_same_technique(self) -> None:
        findings = [
            {"finding_id": "f-1", "reasons": ["tool-name-mismatch"], "severity": "critical"},
            {"finding_id": "f-2", "reasons": ["argument-digest-mismatch"], "severity": "high"},
        ]
        layer = build_navigator_layer(findings)
        self.assertEqual(len(layer["techniques"]), 1)
        self.assertEqual(layer["techniques"][0]["score"], 2)
        self.assertEqual(layer["techniques"][0]["color"], "#ff0000")

    def test_multiple_techniques(self) -> None:
        findings = [
            {"finding_id": "f-1", "reasons": ["tool-name-mismatch"], "severity": "critical"},
            {"finding_id": "f-2", "reasons": ["agent-id-mismatch"], "severity": "medium"},
            {"finding_id": "f-3", "reasons": ["lateral-resource-access"], "severity": "high"},
        ]
        layer = build_navigator_layer(findings)
        tids = {t["techniqueID"] for t in layer["techniques"]}
        self.assertEqual(tids, {"T1036", "T1078", "T1021"})

    def test_severity_escalation(self) -> None:
        findings = [
            {"finding_id": "f-1", "reasons": ["missing-transcript"], "severity": "medium"},
            {"finding_id": "f-2", "reasons": ["trace-id-mismatch"], "severity": "high"},
        ]
        layer = build_navigator_layer(findings)
        t1070 = [t for t in layer["techniques"] if t["techniqueID"] == "T1070"]
        self.assertEqual(len(t1070), 1)
        self.assertEqual(t1070[0]["color"], "#ff6600")

    def test_custom_name(self) -> None:
        layer = build_navigator_layer([], name="test-analysis")
        self.assertEqual(layer["name"], "test-analysis")

    def test_layer_structure(self) -> None:
        layer = build_navigator_layer([{"finding_id": "f-1", "reasons": ["tool-name-mismatch"], "severity": "critical"}])
        self.assertIn("versions", layer)
        self.assertIn("domain", layer)
        self.assertIn("gradient", layer)
        self.assertEqual(layer["versions"]["layer"], "4.5")


class NavigatorCLITest(unittest.TestCase):
    def test_navigator_layer_flag(self) -> None:
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
                "--navigator-layer",
            ])
            cli._run(args)

            layer_path = results_dir / "navigator_layer.json"
            self.assertTrue(layer_path.exists())
            layer = json.loads(layer_path.read_text())
            self.assertEqual(layer["domain"], "enterprise-attack")
            self.assertIsInstance(layer["techniques"], list)
            self.assertGreater(len(layer["techniques"]), 0)
            for t in layer["techniques"]:
                self.assertIn("techniqueID", t)
                self.assertTrue(t["techniqueID"].startswith("T"))

    def test_navigator_layer_with_filter(self) -> None:
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
                "--navigator-layer",
                "--min-severity", "high",
            ])
            cli._run(args)

            layer = json.loads((results_dir / "navigator_layer.json").read_text())
            for t in layer["techniques"]:
                self.assertIn(t["color"], ("#ff0000", "#ff6600"))


if __name__ == "__main__":
    unittest.main()
