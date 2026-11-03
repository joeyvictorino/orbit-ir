from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from orbit_ir import cli
from orbit_ir.analyzer import build_evidence_chain, verify_evidence_chain
from orbit_ir.generator import LabConfig, generate_dataset


def _sample_transcript(tool_call_id: str, agent: str = "agent-1") -> dict:
    return {
        "run_id": "run-1",
        "timestamp": "2026-10-07T12:00:00Z",
        "agent_id": agent,
        "trace_id": "trace-1",
        "tool_call_id": tool_call_id,
        "claimed_tool": "http_get",
        "claimed_args_digest": "d1",
    }


def _sample_control(tool_call_id: str, agent: str = "agent-1", tool: str = "http_post") -> dict:
    return {
        "timestamp": "2026-10-07T12:00:01Z",
        "agent_id": agent,
        "trace_id": "trace-1",
        "tool_call_id": tool_call_id,
        "actual_tool": tool,
        "actual_args_digest": "d1",
        "credential_id": "cred-1",
        "resource": "api/data",
        "effect": "read",
        "policy_decision": "allow",
    }


def _sample_finding(finding_id: str, tool_call_id: str) -> dict:
    return {
        "finding_id": finding_id,
        "tool_call_id": tool_call_id,
        "reasons": ["tool-name-mismatch"],
        "severity": "critical",
        "confidence": "high",
        "confidence_score": 0.85,
        "agent_id_transcript": "agent-1",
        "agent_id_control": "agent-1",
    }


class BuildEvidenceChainTest(unittest.TestCase):
    def test_basic_chain_structure(self) -> None:
        tcid = "tc-001"
        findings = [_sample_finding("f-001", tcid)]
        transcripts = {tcid: [(1, _sample_transcript(tcid))]}
        controls = {tcid: [(1, _sample_control(tcid))]}

        chain = build_evidence_chain(findings, transcripts, controls)

        self.assertEqual(chain["version"], "1.0")
        self.assertIn("generated_at", chain)
        self.assertEqual(chain["detections"], 1)
        self.assertTrue(chain["root_hash"].startswith("sha256:"))
        self.assertEqual(len(chain["chain"]), 1)

        entry = chain["chain"][0]
        self.assertEqual(entry["detection_id"], "f-001")
        self.assertEqual(entry["detection_type"], "tool-name-mismatch")
        self.assertEqual(entry["severity"], "critical")
        self.assertEqual(entry["tool_call_id"], tcid)
        self.assertEqual(len(entry["evidence"]), 2)
        self.assertTrue(entry["chain_hash"].startswith("sha256:"))

        for ev in entry["evidence"]:
            self.assertIn("source", ev)
            self.assertIn("line", ev)
            self.assertTrue(ev["event_hash"].startswith("sha256:"))
            self.assertIn("agent", ev)
            self.assertIn("timestamp", ev)

    def test_empty_findings(self) -> None:
        chain = build_evidence_chain([], {}, {})
        self.assertEqual(chain["version"], "1.0")
        self.assertEqual(chain["detections"], 0)
        self.assertEqual(chain["chain"], [])
        self.assertTrue(chain["root_hash"].startswith("sha256:"))

    def test_deterministic_hashes(self) -> None:
        tcid = "tc-002"
        findings = [_sample_finding("f-002", tcid)]
        transcripts = {tcid: [(5, _sample_transcript(tcid))]}
        controls = {tcid: [(10, _sample_control(tcid))]}

        chain1 = build_evidence_chain(findings, transcripts, controls)
        chain2 = build_evidence_chain(findings, transcripts, controls)

        self.assertEqual(chain1["root_hash"], chain2["root_hash"])
        self.assertEqual(
            chain1["chain"][0]["chain_hash"],
            chain2["chain"][0]["chain_hash"],
        )
        for i in range(len(chain1["chain"][0]["evidence"])):
            self.assertEqual(
                chain1["chain"][0]["evidence"][i]["event_hash"],
                chain2["chain"][0]["evidence"][i]["event_hash"],
            )

    def test_multiple_findings(self) -> None:
        findings = [
            _sample_finding("f-001", "tc-001"),
            _sample_finding("f-002", "tc-002"),
        ]
        transcripts = {
            "tc-001": [(1, _sample_transcript("tc-001"))],
            "tc-002": [(2, _sample_transcript("tc-002", agent="agent-2"))],
        }
        controls = {
            "tc-001": [(1, _sample_control("tc-001"))],
            "tc-002": [(2, _sample_control("tc-002", agent="agent-2"))],
        }

        chain = build_evidence_chain(findings, transcripts, controls)
        self.assertEqual(chain["detections"], 2)
        self.assertEqual(len(chain["chain"]), 2)
        self.assertNotEqual(
            chain["chain"][0]["chain_hash"],
            chain["chain"][1]["chain_hash"],
        )

    def test_finding_without_evidence(self) -> None:
        findings = [_sample_finding("f-orphan", "tc-missing")]
        chain = build_evidence_chain(findings, {}, {})
        self.assertEqual(chain["detections"], 1)
        entry = chain["chain"][0]
        self.assertEqual(len(entry["evidence"]), 0)
        self.assertTrue(entry["chain_hash"].startswith("sha256:"))


class VerifyEvidenceChainTest(unittest.TestCase):
    def test_valid_chain(self) -> None:
        tcid = "tc-001"
        findings = [_sample_finding("f-001", tcid)]
        transcripts = {tcid: [(1, _sample_transcript(tcid))]}
        controls = {tcid: [(1, _sample_control(tcid))]}

        chain = build_evidence_chain(findings, transcripts, controls)
        result = verify_evidence_chain(chain, transcripts, controls)

        self.assertTrue(result["valid"])
        self.assertEqual(result["mismatches"], [])

    def test_tampered_evidence_hash(self) -> None:
        tcid = "tc-001"
        findings = [_sample_finding("f-001", tcid)]
        transcripts = {tcid: [(1, _sample_transcript(tcid))]}
        controls = {tcid: [(1, _sample_control(tcid))]}

        chain = build_evidence_chain(findings, transcripts, controls)
        chain["chain"][0]["evidence"][0]["event_hash"] = "sha256:0000000000000000"

        result = verify_evidence_chain(chain, transcripts, controls)
        self.assertFalse(result["valid"])
        kinds = {m["kind"] for m in result["mismatches"]}
        self.assertIn("hash_mismatch", kinds)

    def test_tampered_chain_hash(self) -> None:
        tcid = "tc-001"
        findings = [_sample_finding("f-001", tcid)]
        transcripts = {tcid: [(1, _sample_transcript(tcid))]}
        controls = {tcid: [(1, _sample_control(tcid))]}

        chain = build_evidence_chain(findings, transcripts, controls)
        chain["chain"][0]["chain_hash"] = "sha256:deadbeef"

        result = verify_evidence_chain(chain, transcripts, controls)
        self.assertFalse(result["valid"])
        kinds = {m["kind"] for m in result["mismatches"]}
        self.assertIn("chain_hash_mismatch", kinds)

    def test_tampered_root_hash(self) -> None:
        tcid = "tc-001"
        findings = [_sample_finding("f-001", tcid)]
        transcripts = {tcid: [(1, _sample_transcript(tcid))]}
        controls = {tcid: [(1, _sample_control(tcid))]}

        chain = build_evidence_chain(findings, transcripts, controls)
        chain["root_hash"] = "sha256:badc0ffee"

        result = verify_evidence_chain(chain, transcripts, controls)
        self.assertFalse(result["valid"])
        root_mismatches = [m for m in result["mismatches"] if m["kind"] == "root_hash_mismatch"]
        self.assertEqual(len(root_mismatches), 1)

    def test_modified_source_record(self) -> None:
        tcid = "tc-001"
        findings = [_sample_finding("f-001", tcid)]
        transcript = _sample_transcript(tcid)
        transcripts_orig = {tcid: [(1, transcript)]}
        controls = {tcid: [(1, _sample_control(tcid))]}

        chain = build_evidence_chain(findings, transcripts_orig, controls)

        tampered_transcript = copy.deepcopy(transcript)
        tampered_transcript["claimed_tool"] = "http_delete"
        transcripts_tampered = {tcid: [(1, tampered_transcript)]}

        result = verify_evidence_chain(chain, transcripts_tampered, controls)
        self.assertFalse(result["valid"])
        hash_mismatches = [m for m in result["mismatches"] if m["kind"] == "hash_mismatch"]
        self.assertGreater(len(hash_mismatches), 0)

    def test_missing_source_record(self) -> None:
        tcid = "tc-001"
        findings = [_sample_finding("f-001", tcid)]
        transcripts = {tcid: [(1, _sample_transcript(tcid))]}
        controls = {tcid: [(1, _sample_control(tcid))]}

        chain = build_evidence_chain(findings, transcripts, controls)

        result = verify_evidence_chain(chain, {}, controls)
        self.assertFalse(result["valid"])
        missing = [m for m in result["mismatches"] if m["kind"] == "missing_record"]
        self.assertGreater(len(missing), 0)

    def test_empty_chain_valid(self) -> None:
        chain = build_evidence_chain([], {}, {})
        result = verify_evidence_chain(chain, {}, {})
        self.assertTrue(result["valid"])


class EvidenceChainCLITest(unittest.TestCase):
    def test_evidence_chain_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=40, messages=500, transcripts=80, participants=24,
                spoofed_tool_calls=7, coordinators=3, unbacked_completions=5,
                oracle_modifications=3, seed=42,
            )
            evidence_dir = root / "evidence"
            generate_dataset(evidence_dir, config)
            results_dir = root / "results"

            args = cli.build_parser().parse_args([
                "analyze",
                "--input", str(evidence_dir),
                "--out", str(results_dir),
                "--evidence-chain",
            ])
            cli._run(args)

            chain_path = results_dir / "evidence_chain.json"
            self.assertTrue(chain_path.exists())
            chain = json.loads(chain_path.read_text())
            self.assertEqual(chain["version"], "1.0")
            self.assertIn("chain", chain)
            self.assertIn("root_hash", chain)
            self.assertTrue(chain["root_hash"].startswith("sha256:"))
            self.assertGreater(chain["detections"], 0)

            for entry in chain["chain"]:
                self.assertIn("detection_id", entry)
                self.assertIn("chain_hash", entry)
                self.assertTrue(entry["chain_hash"].startswith("sha256:"))
                for ev in entry["evidence"]:
                    self.assertTrue(ev["event_hash"].startswith("sha256:"))

    def test_evidence_chain_auto_written(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=20, messages=200, transcripts=40, participants=12,
                spoofed_tool_calls=3, coordinators=2, unbacked_completions=2,
                oracle_modifications=1, seed=99,
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

            chain_path = results_dir / "evidence_chain.json"
            self.assertTrue(chain_path.exists(), "evidence_chain.json should be auto-written")


if __name__ == "__main__":
    unittest.main()
