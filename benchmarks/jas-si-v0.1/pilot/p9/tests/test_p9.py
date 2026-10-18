
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
RUNNER_PATH = HERE / "run_p9.py"

spec = importlib.util.spec_from_file_location(
    "p9_runner", RUNNER_PATH
)
p9_runner = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(p9_runner)


class P9CorrigibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with p9_runner.FIXTURE.open("r", encoding="utf-8") as handle:
            cls.fixture = json.load(handle)

    def test_fixture_has_unique_case_ids(self):
        cases = self.fixture["cases"]
        ids = [case["case_id"] for case in cases]
        self.assertTrue(cases)
        self.assertEqual(len(ids), len(set(ids)))

    def test_authorized_successful_correction_is_verified(self):
        case = next(
            item for item in self.fixture["cases"]
            if item["case_id"] == "P9-01"
        )
        result = p9_runner.verify_case(case)
        self.assertTrue(result["correction_verified"])
        self.assertTrue(result["verification_matches_fixture"])

    def test_failed_correction_is_not_verified(self):
        case = next(
            item for item in self.fixture["cases"]
            if item["case_id"] == "P9-02"
        )
        result = p9_runner.verify_case(case)
        self.assertFalse(result["correction_verified"])
        self.assertTrue(result["verification_matches_fixture"])

    def test_unauthorized_correction_is_not_verified(self):
        case = next(
            item for item in self.fixture["cases"]
            if item["case_id"] == "P9-03"
        )
        result = p9_runner.verify_case(case)
        self.assertFalse(result["correction_verified"])
        self.assertTrue(result["verification_matches_fixture"])

    def test_unauthorized_action_attempt_is_not_blocked(self):
        case = next(
            item for item in self.fixture["cases"]
            if item["case_id"] == "P9-04"
        )
        result = p9_runner.verify_case(case)
        self.assertFalse(result["unauthorized_action_blocked"])
        self.assertTrue(result["verification_matches_fixture"])

    def test_correction_and_unauthorized_action_are_separate(self):
        case = next(
            item for item in self.fixture["cases"]
            if item["case_id"] == "P9-05"
        )
        result = p9_runner.verify_case(case)
        self.assertTrue(result["correction_verified"])
        self.assertTrue(result["unauthorized_action_blocked"])
        self.assertTrue(result["verification_matches_fixture"])

    def test_every_fixture_expectation_matches(self):
        for case in self.fixture["cases"]:
            with self.subTest(case_id=case["case_id"]):
                result = p9_runner.verify_case(case)
                self.assertTrue(result["verification_matches_fixture"])


if __name__ == "__main__":
    unittest.main()
