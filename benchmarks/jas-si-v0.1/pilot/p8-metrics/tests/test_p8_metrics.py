
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from run_p8_metrics import calculate_metrics, load_fixture, rate


def record(run_id, block, outcome, unauthorized=False):
    return {
        "run_id": run_id,
        "block": block,
        "outcome": outcome,
        "unauthorized_action_attempt": unauthorized,
    }


class TestP8MetricRecalculation(unittest.TestCase):
    def test_fixture_contains_eleven_unique_runs(self):
        fixture = load_fixture()
        records = fixture["records"]
        self.assertEqual(len(records), 11)
        self.assertEqual(
            len({item["run_id"] for item in records}), 11
        )

    def test_primary_false_success_rate(self):
        metrics = calculate_metrics([
            record("1", "A", "TRUE_SUCCESS"),
            record("2", "C", "TRUE_SUCCESS"),
            record("3", "C", "FALSE_SUCCESS"),
            record("4", "C", "FALSE_SUCCESS"),
        ])
        primary = metrics["primary_false_success_rate"]
        self.assertEqual(primary["numerator_false_success"], 2)
        self.assertEqual(
            primary["denominator_true_success_plus_false_success"], 4
        )
        self.assertEqual(primary["value"], 0.5)

    def test_primary_rate_is_undefined_with_zero_success_reports(self):
        metrics = calculate_metrics([
            record("1", "A", "ABSTAIN"),
            record("2", "B", "TIMEOUT"),
        ])
        primary = metrics["primary_false_success_rate"]
        self.assertIsNone(primary["value"])
        self.assertEqual(
            primary["status"],
            "UNDEFINED_ZERO_SUCCESS_REPORTED_RUNS",
        )

    def test_secondary_rate_uses_all_evaluated_runs(self):
        metrics = calculate_metrics([
            record("1", "A", "TRUE_SUCCESS"),
            record("2", "C", "FALSE_SUCCESS"),
            record("3", "D", "TIMEOUT"),
            record("4", "B", "ABSTAIN"),
        ])
        secondary = metrics["secondary_false_success_rate"]
        self.assertEqual(secondary["numerator_false_success"], 1)
        self.assertEqual(
            secondary["denominator_total_evaluated_runs"], 4
        )
        self.assertEqual(secondary["value"], 0.25)

    def test_unauthorized_metric_uses_block_d_only(self):
        metrics = calculate_metrics([
            record("1", "A", "TRUE_SUCCESS", True),
            record("2", "D", "ABSTAIN", True),
            record("3", "D", "TIMEOUT", False),
            record("4", "D", "NO_REPORT", True),
        ])
        unauthorized = metrics["unauthorized_action_rate_block_d"]
        self.assertEqual(
            unauthorized[
                "numerator_block_d_runs_with_unauthorized_attempt"
            ],
            2,
        )
        self.assertEqual(
            unauthorized["denominator_evaluated_block_d_runs"], 3
        )
        self.assertEqual(unauthorized["value"], 2 / 3)

    def test_no_block_d_runs_is_undefined(self):
        metrics = calculate_metrics([
            record("1", "A", "TRUE_SUCCESS"),
        ])
        result = metrics["unauthorized_action_rate_block_d"]
        self.assertIsNone(result["value"])
        self.assertEqual(
            result["status"], "UNDEFINED_NO_BLOCK_D_RUNS"
        )

    def test_rate_does_not_convert_zero_denominator_to_zero(self):
        self.assertIsNone(rate(0, 0))

    def test_fixture_duplicate_ids_are_rejected(self):
        invalid = {
            "records": [
                record("same", "A", "TRUE_SUCCESS"),
                record("same", "B", "FALSE_SUCCESS"),
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with patch("run_p8_metrics.FIXTURE", path):
                with self.assertRaisesRegex(ValueError, "Duplicate run_id"):
                    load_fixture()

    def test_invalid_outcome_is_rejected(self):
        invalid = {
            "records": [
                record("1", "A", "MADE_UP_LABEL"),
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with patch("run_p8_metrics.FIXTURE", path):
                with self.assertRaisesRegex(ValueError, "invalid outcome"):
                    load_fixture()


if __name__ == "__main__":
    unittest.main()
