from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


P3_ROOT = Path(__file__).resolve().parents[1]
PILOT_ROOT = P3_ROOT.parent

sys.path.insert(0, str(P3_ROOT))

import run_p3  # noqa: E402


FIXTURE_PATH = P3_ROOT / "fixtures" / "p3_multi_agent_cases.json"


class TestP3MultiAgentControl(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cases = run_p3.load_json(FIXTURE_PATH)

        verifier_module = run_p3.load_module(
            "jas_si_p3_test_verifier",
            PILOT_ROOT / "verifier" / "oracle_verifier.py",
        )

        cls.verifier = verifier_module.IndependentVerifier()

    def test_all_cases_have_unique_ids(self):
        ids = [case["case_id"] for case in self.cases]

        self.assertEqual(len(ids), len(set(ids)))

    def test_single_agent_cases_exist(self):
        conditions = {
            case["condition"]
            for case in self.cases
        }

        self.assertIn("SINGLE_AGENT", conditions)

    def test_multi_agent_cases_exist(self):
        conditions = {
            case["condition"]
            for case in self.cases
        }

        self.assertIn("MULTI_AGENT", conditions)

    def test_false_success_is_detected(self):
        case = next(
            case
            for case in self.cases
            if case["case_id"] == "P3-E"
        )

        result = self.verifier.verify(
            expected_outcome=case["expected_outcome"],
            observed_outcome=case["observed_outcome"],
            reported_status=case["reported_status"],
        )

        self.assertEqual(
            result.outcome_label,
            "FALSE_SUCCESS",
        )

        self.assertFalse(result.verified)

    def test_false_failure_is_corrected_by_observation(self):
        case = next(
            case
            for case in self.cases
            if case["case_id"] == "P3-F"
        )

        result = self.verifier.verify(
            expected_outcome=case["expected_outcome"],
            observed_outcome=case["observed_outcome"],
            reported_status=case["reported_status"],
        )

        self.assertEqual(
            result.outcome_label,
            "TRUE_SUCCESS",
        )

        self.assertTrue(result.verified)

    def test_multi_agent_consensus_cannot_override_reality(self):
        case = next(
            case
            for case in self.cases
            if case["case_id"] == "P3-G"
        )

        result = self.verifier.verify(
            expected_outcome=case["expected_outcome"],
            observed_outcome=case["observed_outcome"],
            reported_status=case["reported_status"],
        )

        self.assertEqual(
            result.outcome_label,
            "FALSE_SUCCESS",
        )

        self.assertFalse(result.verified)

    def test_verifier_is_independent_of_agent_report(self):
        for case in self.cases:
            result = self.verifier.verify(
                expected_outcome=case["expected_outcome"],
                observed_outcome=case["observed_outcome"],
                reported_status=case["reported_status"],
            )

            self.assertTrue(
                result.independent_of_agent_report
            )

    def test_all_fixture_cases_pass(self):
        results = [
            run_p3.verify_case(
                case,
                self.verifier,
            )
            for case in self.cases
        ]

        self.assertTrue(
            all(result["passed"] for result in results)
        )

    def test_summary_is_all_pass(self):
        results = [
            run_p3.verify_case(
                case,
                self.verifier,
            )
            for case in self.cases
        ]

        summary = run_p3.build_summary(results)

        self.assertTrue(summary["all_cases_passed"])
        self.assertEqual(summary["failed_cases"], 0)
        self.assertEqual(summary["pass_rate"], 1.0)
        self.assertTrue(
            summary["agent_report_is_not_ground_truth"]
        )


if __name__ == "__main__":
    unittest.main()
