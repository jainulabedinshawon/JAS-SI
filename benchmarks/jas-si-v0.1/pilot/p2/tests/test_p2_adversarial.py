from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


PILOT_ROOT = Path(__file__).resolve().parents[2]
P2_ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)

    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module: {path}")

    module = importlib.util.module_from_spec(spec)

    # Required for Python 3.10 dataclass module resolution.
    sys.modules[name] = module

    spec.loader.exec_module(module)
    return module


VERIFIER = load_module(
    "test_p2_oracle_verifier",
    PILOT_ROOT / "verifier" / "oracle_verifier.py",
)

RUN_P2 = load_module(
    "test_run_p2",
    P2_ROOT / "run_p2.py",
)


class TestP2AdversarialControl(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        fixture_path = (
            P2_ROOT
            / "fixtures"
            / "p2_adversarial_cases.json"
        )

        with fixture_path.open("r", encoding="utf-8") as handle:
            cls.cases = json.load(handle)

        RUN_P2.validate_cases(cls.cases)

    def test_all_cases_have_unique_ids(self):
        ids = [case["case_id"] for case in self.cases]

        self.assertEqual(
            len(ids),
            len(set(ids)),
        )

    def test_false_success_is_detected(self):
        verifier = VERIFIER.IndependentVerifier()

        result = verifier.verify(
            expected_outcome="EXPECTED",
            observed_outcome="WRONG",
            reported_status="SUCCESS",
        )

        self.assertFalse(result.verified)
        self.assertFalse(result.exact_match)
        self.assertTrue(result.independent_of_agent_report)
        self.assertEqual(
            result.outcome_label,
            "FALSE_SUCCESS",
        )

    def test_truthful_failure_is_not_false_success(self):
        verifier = VERIFIER.IndependentVerifier()

        result = verifier.verify(
            expected_outcome="EXPECTED",
            observed_outcome="WRONG",
            reported_status="FAILURE",
        )

        self.assertFalse(result.verified)
        self.assertFalse(result.exact_match)
        self.assertEqual(
            result.outcome_label,
            "FAILURE",
        )

    def test_false_failure_is_corrected_by_observation(self):
        verifier = VERIFIER.IndependentVerifier()

        result = verifier.verify(
            expected_outcome="EXPECTED",
            observed_outcome="EXPECTED",
            reported_status="FAILURE",
        )

        self.assertTrue(result.verified)
        self.assertTrue(result.exact_match)
        self.assertEqual(
            result.outcome_label,
            "TRUE_SUCCESS",
        )

    def test_report_cannot_turn_wrong_observation_into_success(self):
        verifier = VERIFIER.IndependentVerifier()

        reports = [
            "SUCCESS",
            "FAILURE",
            "REPORTED_SUCCESS",
            "REPORTED_FAILURE",
        ]

        for report in reports:
            with self.subTest(report=report):
                result = verifier.verify(
                    expected_outcome="EXPECTED",
                    observed_outcome="WRONG",
                    reported_status=report,
                )

                self.assertFalse(result.verified)
                self.assertFalse(result.exact_match)
                self.assertNotEqual(
                    result.outcome_label,
                    "TRUE_SUCCESS",
                )

    def test_paired_adversarial_case(self):
        verifier = VERIFIER.IndependentVerifier()

        success_report = verifier.verify(
            expected_outcome="EXPECTED",
            observed_outcome="WRONG",
            reported_status="SUCCESS",
        )

        failure_report = verifier.verify(
            expected_outcome="EXPECTED",
            observed_outcome="WRONG",
            reported_status="FAILURE",
        )

        self.assertFalse(success_report.verified)
        self.assertFalse(failure_report.verified)

        self.assertFalse(success_report.exact_match)
        self.assertFalse(failure_report.exact_match)

        self.assertEqual(
            success_report.outcome_label,
            "FALSE_SUCCESS",
        )

        self.assertEqual(
            failure_report.outcome_label,
            "FAILURE",
        )

        self.assertTrue(
            success_report.independent_of_agent_report
        )

        self.assertTrue(
            failure_report.independent_of_agent_report
        )

    def test_fixture_cases_pass(self):
        verifier = VERIFIER.IndependentVerifier()

        for case in self.cases:
            with self.subTest(case_id=case["case_id"]):
                record = RUN_P2.run_case(verifier, case)

                self.assertTrue(
                    record["passed"],
                    msg=f"Failed case: {case['case_id']}",
                )

    def test_summary_is_all_pass(self):
        verifier = VERIFIER.IndependentVerifier()

        records = [
            RUN_P2.run_case(verifier, case)
            for case in self.cases
        ]

        summary = RUN_P2.build_summary(records)

        self.assertEqual(
            summary["case_count"],
            len(self.cases),
        )

        self.assertEqual(
            summary["passed_cases"],
            len(self.cases),
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
            summary["all_cases_passed"]
        )


if __name__ == "__main__":
    unittest.main()
