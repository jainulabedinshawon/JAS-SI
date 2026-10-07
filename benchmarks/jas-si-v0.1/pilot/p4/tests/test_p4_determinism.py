from __future__ import annotations

import sys
import unittest
from pathlib import Path


P4_ROOT = Path(__file__).resolve().parents[1]
PILOT_ROOT = P4_ROOT.parent

sys.path.insert(0, str(P4_ROOT))

import run_p4  # noqa: E402


FIXTURE_PATH = (
    P4_ROOT
    / "fixtures"
    / "p4_determinism_cases.json"
)


class TestP4Determinism(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cases = run_p4.load_json(FIXTURE_PATH)

        verifier_module = run_p4.load_module(
            "jas_si_p4_test_verifier",
            PILOT_ROOT / "verifier" / "oracle_verifier.py",
        )

        cls.verifier = (
            verifier_module.IndependentVerifier()
        )

    def test_all_cases_have_unique_ids(self):
        ids = [
            case["case_id"]
            for case in self.cases
        ]

        self.assertEqual(
            len(ids),
            len(set(ids)),
        )

    def test_correct_observation_is_verified(self):
        case = next(
            case
            for case in self.cases
            if case["case_id"] == "P4-A"
        )

        result = self.verifier.verify(
            expected_outcome=case["expected_outcome"],
            observed_outcome=case["observed_outcome"],
            reported_status=case["reported_status"],
        )

        self.assertTrue(result.verified)
        self.assertTrue(result.exact_match)

    def test_wrong_observation_is_not_verified(self):
        case = next(
            case
            for case in self.cases
            if case["case_id"] == "P4-C"
        )

        result = self.verifier.verify(
            expected_outcome=case["expected_outcome"],
            observed_outcome=case["observed_outcome"],
            reported_status=case["reported_status"],
        )

        self.assertFalse(result.verified)
        self.assertFalse(result.exact_match)

    def test_correct_reality_is_report_invariant(self):
        results = []

        for report in ("SUCCESS", "FAILURE"):
            result = self.verifier.verify(
                expected_outcome="EXPECTED",
                observed_outcome="EXPECTED",
                reported_status=report,
            )

            results.append(
                (
                    result.verified,
                    result.exact_match,
                    result.verification_basis,
                )
            )

        self.assertEqual(
            results[0],
            results[1],
        )

    def test_wrong_reality_is_report_invariant(self):
        results = []

        for report in ("SUCCESS", "FAILURE"):
            result = self.verifier.verify(
                expected_outcome="EXPECTED",
                observed_outcome="WRONG",
                reported_status=report,
            )

            results.append(
                (
                    result.verified,
                    result.exact_match,
                    result.verification_basis,
                )
            )

        self.assertEqual(
            results[0],
            results[1],
        )

    def test_repeated_verification_is_deterministic(self):
        case = next(
            case
            for case in self.cases
            if case["case_id"] == "P4-E"
        )

        snapshots = []

        for _ in range(10):
            result = self.verifier.verify(
                expected_outcome=case["expected_outcome"],
                observed_outcome=case["observed_outcome"],
                reported_status=case["reported_status"],
            )

            snapshots.append(
                run_p4.verification_snapshot(result)
            )

        self.assertTrue(
            all(
                snapshot == snapshots[0]
                for snapshot in snapshots
            )
        )

    def test_core_report_invariance_control(self):
        result = run_p4.run_report_invariance_control(
            self.verifier
        )

        self.assertTrue(
            result["all_core_invariants_hold"]
        )

    def test_all_fixture_cases_pass(self):
        results = [
            run_p4.run_case(
                case,
                self.verifier,
            )
            for case in self.cases
        ]

        self.assertTrue(
            all(
                result["passed"]
                for result in results
            )
        )

    def test_summary_is_all_pass(self):
        results = [
            run_p4.run_case(
                case,
                self.verifier,
            )
            for case in self.cases
        ]

        report_invariance = (
            run_p4.run_report_invariance_control(
                self.verifier
            )
        )

        summary = run_p4.build_summary(
            results,
            report_invariance,
        )

        self.assertTrue(
            summary["all_cases_passed"]
        )

        self.assertEqual(
            summary["failed_cases"],
            0,
        )

        self.assertEqual(
            summary["pass_rate"],
            1.0,
        )

        self.assertTrue(
            summary["report_invariance"][
                "all_core_invariants_hold"
            ]
        )


if __name__ == "__main__":
    unittest.main()
