from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

P6_ROOT = Path(__file__).resolve().parents[1]

if str(P6_ROOT) not in sys.path:
    sys.path.insert(0, str(P6_ROOT))

import run_p6


class TestP6LabelAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_path = (
            P6_ROOT / "fixtures" / "p6_label_audit_cases.json"
        )

        with fixture_path.open("r", encoding="utf-8") as handle:
            cls.cases = json.load(handle)

        run_p6.validate_fixture(cls.cases)

    def get_case(self, case_id):
        return next(
            case for case in self.cases
            if case["case_id"] == case_id
        )

    def test_case_ids_are_unique(self):
        ids = [case["case_id"] for case in self.cases]
        self.assertEqual(len(ids), len(set(ids)))

    def test_all_four_outcome_labels_are_derived(self):
        combinations = [
            (True, True, "TRUE_SUCCESS"),
            (False, True, "FALSE_SUCCESS"),
            (False, False, "FAILURE"),
            (True, False, "FALSE_FAILURE"),
        ]

        for achieved, reported, expected in combinations:
            with self.subTest(expected=expected):
                self.assertEqual(
                    run_p6.derive_expected_label(achieved, reported),
                    expected,
                )

    def test_correct_labels_are_accepted(self):
        valid_cases = [
            case for case in self.cases
            if case["expected_valid"]
        ]

        self.assertEqual(len(valid_cases), 4)

        for case in valid_cases:
            with self.subTest(case_id=case["case_id"]):
                result = run_p6.evaluate_case(case)
                self.assertTrue(result["actual_valid"])
                self.assertTrue(result["label_matches_ground_truth"])
                self.assertTrue(result["passed"])

    def test_incorrect_labels_are_rejected(self):
        invalid_cases = [
            case for case in self.cases
            if not case["expected_valid"]
        ]

        self.assertEqual(len(invalid_cases), 4)

        for case in invalid_cases:
            with self.subTest(case_id=case["case_id"]):
                result = run_p6.evaluate_case(case)
                self.assertFalse(result["actual_valid"])
                self.assertFalse(result["label_matches_ground_truth"])
                self.assertTrue(result["passed"])

    def test_invalid_outcome_label_is_rejected(self):
        case = dict(self.cases[0])
        case["observed_label"] = "UNKNOWN_LABEL"

        with self.assertRaises(ValueError):
            run_p6.validate_fixture([case])

    def test_non_boolean_state_is_rejected(self):
        with self.assertRaises(ValueError):
            run_p6.derive_expected_label(1, True)

    def test_non_boolean_report_is_rejected(self):
        with self.assertRaises(ValueError):
            run_p6.derive_expected_label(True, "success")

    def test_all_fixture_expectations_match(self):
        results = [
            run_p6.evaluate_case(case)
            for case in self.cases
        ]

        self.assertTrue(all(result["passed"] for result in results))

    def test_fixture_contains_both_valid_and_invalid_labels(self):
        results = [
            run_p6.evaluate_case(case)
            for case in self.cases
        ]

        self.assertEqual(
            sum(result["actual_valid"] for result in results),
            4,
        )
        self.assertEqual(
            sum(not result["actual_valid"] for result in results),
            4,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
