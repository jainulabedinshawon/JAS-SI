
from __future__ import annotations

import sys
import unittest
from pathlib import Path


PILOT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PILOT_ROOT))

from validate_p3_determinism import (  # noqa: E402
    run_once,
    validate_determinism,
    without_runtime_timestamps,
)


class P3DeterminismTests(unittest.TestCase):
    def test_repeated_runs_have_identical_stable_results(self):
        first = run_once()
        second = run_once()

        self.assertEqual(
            without_runtime_timestamps(first),
            without_runtime_timestamps(second),
        )

    def test_task_order_is_reproducible(self):
        first = run_once()
        second = run_once()

        self.assertEqual(
            [item["task_id"] for item in first["evidence_records"]],
            [item["task_id"] for item in second["evidence_records"]],
        )

    def test_aggregate_metrics_are_reproducible(self):
        first = run_once()
        second = run_once()

        self.assertEqual(first["task_count"], second["task_count"])
        self.assertEqual(
            first["outcome_counts"],
            second["outcome_counts"],
        )
        self.assertEqual(first["accuracy"], second["accuracy"])

    def test_determinism_gate_reports_pass(self):
        report = validate_determinism()

        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["stable_fields_match"])
        self.assertTrue(report["task_order_match"])
        self.assertTrue(report["aggregate_metrics_match"])
        self.assertEqual(report["runs_compared"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
