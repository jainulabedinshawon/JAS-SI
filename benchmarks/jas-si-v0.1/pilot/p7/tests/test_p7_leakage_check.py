from __future__ import annotations

import unittest

from run_p7 import (
    evaluate_case,
    find_forbidden_keys,
    validate_fixture,
)


FORBIDDEN_KEYS = {
    "ground_truth",
    "expected_outcome",
    "oracle_label",
    "reference_answer",
}


class TestP7LeakageCheck(unittest.TestCase):
    def test_clean_payload_is_accepted(self):
        payload = {
            "task": "Check the record",
            "metadata": {
                "task_id": "T-1"
            }
        }

        findings = find_forbidden_keys(payload, FORBIDDEN_KEYS)

        self.assertEqual(findings, [])

    def test_forbidden_key_is_detected(self):
        payload = {
            "task": "Check the record",
            "ground_truth": "success"
        }

        findings = find_forbidden_keys(payload, FORBIDDEN_KEYS)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["key"], "ground_truth")
        self.assertEqual(findings[0]["path"], "$.ground_truth")

    def test_nested_forbidden_key_is_detected(self):
        payload = {
            "context": {
                "evaluation": {
                    "expected_outcome": "success"
                }
            }
        }

        findings = find_forbidden_keys(payload, FORBIDDEN_KEYS)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["path"],
            "$.context.evaluation.expected_outcome",
        )

    def test_forbidden_key_inside_array_is_detected(self):
        payload = {
            "records": [
                {"record_id": "R-1"},
                {"oracle_label": "TRUE_SUCCESS"}
            ]
        }

        findings = find_forbidden_keys(payload, FORBIDDEN_KEYS)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["path"],
            "$.records[1].oracle_label",
        )

    def test_multiple_forbidden_keys_are_detected(self):
        payload = {
            "ground_truth": True,
            "details": {
                "reference_answer": "expected answer"
            }
        }

        findings = find_forbidden_keys(payload, FORBIDDEN_KEYS)

        self.assertEqual(len(findings), 2)

    def test_expected_leak_is_a_passing_control(self):
        case = {
            "case_id": "known_leak",
            "agent_payload": {
                "oracle_label": "FAILURE"
            },
            "expected_leakage_detected": True,
        }

        result = evaluate_case(case, FORBIDDEN_KEYS)

        self.assertTrue(result["actual_leakage_detected"])
        self.assertTrue(result["passed"])

    def test_unexpected_leak_fails_control(self):
        case = {
            "case_id": "unexpected_leak",
            "agent_payload": {
                "ground_truth": "hidden"
            },
            "expected_leakage_detected": False,
        }

        result = evaluate_case(case, FORBIDDEN_KEYS)

        self.assertTrue(result["actual_leakage_detected"])
        self.assertFalse(result["passed"])

    def test_fixture_requires_unique_case_ids(self):
        fixture = {
            "forbidden_keys": ["ground_truth"],
            "cases": [
                {
                    "case_id": "duplicate",
                    "agent_payload": {},
                    "expected_leakage_detected": False,
                },
                {
                    "case_id": "duplicate",
                    "agent_payload": {},
                    "expected_leakage_detected": False,
                },
            ],
        }

        with self.assertRaisesRegex(ValueError, "Duplicate case_id"):
            validate_fixture(fixture)

    def test_fixture_rejects_non_boolean_expectation(self):
        fixture = {
            "forbidden_keys": ["ground_truth"],
            "cases": [
                {
                    "case_id": "bad_expectation",
                    "agent_payload": {},
                    "expected_leakage_detected": "false",
                }
            ],
        }

        with self.assertRaisesRegex(ValueError, "must be boolean"):
            validate_fixture(fixture)


if __name__ == "__main__":
    unittest.main()
