from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


P5_ROOT = Path(__file__).resolve().parents[1]

if str(P5_ROOT) not in sys.path:
    sys.path.insert(0, str(P5_ROOT))

import run_p5


class TestP5FloorCeiling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (P5_ROOT / "fixtures" / "p5_floor_ceiling_cases.json").open(
            "r",
            encoding="utf-8",
        ) as handle:
            cls.cases = json.load(handle)

        run_p5.validate_fixture(cls.cases)

    def get_case(self, case_id):
        return next(
            case for case in self.cases
            if case["case_id"] == case_id
        )

    def test_case_ids_are_unique(self):
        ids = [case["case_id"] for case in self.cases]
        self.assertEqual(len(ids), len(set(ids)))

    def test_discriminative_conditions_pass(self):
        result = run_p5.evaluate_case(
            self.get_case("P5-DISCRIMINATIVE")
        )
        self.assertTrue(result["passed"])
        self.assertTrue(result["actual_pass"])

    def test_saturated_conditions_are_rejected(self):
        result = run_p5.evaluate_case(
            self.get_case("P5-SATURATED")
        )
        self.assertTrue(result["passed"])
        self.assertFalse(result["actual_pass"])

    def test_scripted_controls_are_excluded(self):
        result = run_p5.evaluate_case(
            self.get_case("P5-SCRIPTED-CONTROL-EXCLUDED")
        )
        self.assertEqual(result["included_condition_count"], 0)
        self.assertEqual(result["excluded_scripted_control_count"], 2)
        self.assertFalse(result["actual_pass"])
        self.assertTrue(result["expectation_match"])

    def test_metric_formulas(self):
        metrics = run_p5.calculate_metrics(
            {
                "TRUE_SUCCESS": 6,
                "FALSE_SUCCESS": 2,
                "FAILURE": 1,
                "FALSE_FAILURE": 1,
            }
        )

        self.assertAlmostEqual(metrics["FSR"], 0.25)
        self.assertAlmostEqual(metrics["RA"], 0.7)
        self.assertAlmostEqual(metrics["FFR"], 0.5)

    def test_zero_denominator_is_rejected(self):
        with self.assertRaises(ValueError):
            run_p5.calculate_metrics(
                {
                    "TRUE_SUCCESS": 0,
                    "FALSE_SUCCESS": 0,
                    "FAILURE": 1,
                    "FALSE_FAILURE": 0,
                }
            )

    def test_negative_outcome_count_is_rejected(self):
        with self.assertRaises(ValueError):
            run_p5.validate_outcomes(
                {
                    "TRUE_SUCCESS": 1,
                    "FALSE_SUCCESS": 0,
                    "FAILURE": -1,
                    "FALSE_FAILURE": 0,
                },
                "INVALID",
            )

    def test_all_fixture_expectations_match(self):
        results = [
            run_p5.evaluate_case(case)
            for case in self.cases
        ]
        self.assertTrue(all(result["passed"] for result in results))


if __name__ == "__main__":
    unittest.main(verbosity=2)
