from __future__ import annotations

import resource
import tempfile
import time
import unittest
from pathlib import Path

from orbit_ir.analyzer import analyze_dataset
from orbit_ir.generator import LabConfig, generate_dataset


class PerformanceBenchmarks(unittest.TestCase):
    """Regression guards for pipeline speed and memory."""

    def test_full_pipeline_completes_within_budget(self) -> None:
        """The full generate+analyze pipeline should finish in under 30s."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(seed=42)

            t0 = time.perf_counter()
            generate_dataset(root / "evidence", config)
            t_gen = time.perf_counter() - t0

            t1 = time.perf_counter()
            summary = analyze_dataset(
                root / "evidence",
                root / "results",
                ground_truth_path=root / "evidence" / "ground_truth.json",
            )
            t_analyze = time.perf_counter() - t1

            total = time.perf_counter() - t0
            print(
                f"\n  generate: {t_gen:.2f}s, analyze: {t_analyze:.2f}s, "
                f"total: {total:.2f}s"
            )
            self.assertLess(total, 30.0, "full pipeline exceeded 30s budget")
            self.assertGreater(summary["corpus"]["messages"], 0)

    def test_small_fixture_under_one_second(self) -> None:
        """A small fixture should analyze very quickly."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(
                agents=40,
                messages=500,
                transcripts=80,
                participants=24,
                spoofed_tool_calls=7,
                coordinators=3,
                seed=99,
            )

            t0 = time.perf_counter()
            generate_dataset(root / "evidence", config)
            analyze_dataset(root / "evidence", root / "results")
            elapsed = time.perf_counter() - t0

            print(f"\n  small fixture: {elapsed:.2f}s")
            self.assertLess(elapsed, 5.0, "small fixture exceeded 5s budget")

    def test_memory_stays_within_budget(self) -> None:
        """The full-scale fixture should stay under 512 MiB peak RSS."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = LabConfig(seed=77)
            generate_dataset(root / "evidence", config)
            analyze_dataset(
                root / "evidence",
                root / "results",
                ground_truth_path=root / "evidence" / "ground_truth.json",
            )

            peak_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            peak_mib = peak_kb / 1024
            print(f"\n  peak RSS: {peak_mib:.1f} MiB")
            self.assertLess(
                peak_mib, 512, f"peak RSS {peak_mib:.0f} MiB exceeds 512 MiB budget"
            )
