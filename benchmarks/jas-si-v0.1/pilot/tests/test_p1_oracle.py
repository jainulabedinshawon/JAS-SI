from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


PILOT_ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)

    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module: {path}")

    module = importlib.util.module_from_spec(spec)

    # Required for Python 3.10 dataclass module resolution
    # when loading modules dynamically from file paths.
    sys.modules[name] = module

    spec.loader.exec_module(module)
    return module


ORACLE = load_module(
    "test_oracle_agent",
    PILOT_ROOT / "agents" / "oracle_agent.py",
)

VERIFIER = load_module(
    "test_oracle_verifier",
    PILOT_ROOT / "verifier" / "oracle_verifier.py",
)

RUNNER = load_module(
    "test_pilot_runner",
    PILOT_ROOT / "harness" / "pilot_runner.py",
)

RUN_P1 = load_module(
    "test_run_p1",
    PILOT_ROOT / "run_p1.py",
)


class TestP1Oracle(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        fixture_path = PILOT_ROOT / "fixtures" / "p1_tasks.json"

        with fixture_path.open("r", encoding="utf-8") as handle:
            cls.tasks = json.load(handle)

    def test_fixture_is_valid(self):
        RUN_P1.validate_tasks(self.tasks)

    def test_oracle_is_deterministic(self):
        agent = ORACLE.OracleAgent()

        first = agent.run(self.tasks[0])
        second = agent.run(self.tasks[0])

        self.assertEqual(first, second)

    def test_oracle_observes_expected_outcome(self):
        agent = ORACLE.OracleAgent()

        result = agent.run(self.tasks[0])

        expected = self.tasks[0]["ground_truth"]["expected_outcome"]

        self.assertEqual(result.observed_outcome, expected)
        self.assertEqual(result.reported_outcome, expected)
        self.assertEqual(result.reported_status, "SUCCESS")

    def test_true_success_verification(self):
        verifier = VERIFIER.IndependentVerifier()

        result = verifier.verify(
            expected_outcome="EXPECTED",
            observed_outcome="EXPECTED",
            reported_status="SUCCESS",
        )

        self.assertTrue(result.verified)
        self.assertTrue(result.exact_match)
        self.assertTrue(result.independent_of_agent_report)
        self.assertEqual(result.outcome_label, "TRUE_SUCCESS")

    def test_false_success_detection(self):
        verifier = VERIFIER.IndependentVerifier()

        result = verifier.verify(
            expected_outcome="EXPECTED",
            observed_outcome="WRONG",
            reported_status="SUCCESS",
        )

        self.assertFalse(result.verified)
        self.assertFalse(result.exact_match)
        self.assertTrue(result.independent_of_agent_report)
        self.assertEqual(result.outcome_label, "FALSE_SUCCESS")

    def test_failure_classification(self):
        verifier = VERIFIER.IndependentVerifier()

        result = verifier.verify(
            expected_outcome="EXPECTED",
            observed_outcome="WRONG",
            reported_status="FAILURE",
        )

        self.assertFalse(result.verified)
        self.assertEqual(result.outcome_label, "FAILURE")

    def test_runner_generates_evidence(self):
        agent = ORACLE.OracleAgent()
        verifier = VERIFIER.IndependentVerifier()
        runner = RUNNER.PilotRunner(agent, verifier)

        evidence = runner.run(self.tasks)

        self.assertEqual(len(evidence), len(self.tasks))

        for record in evidence:
            RUN_P1.validate_evidence_record(record)

            self.assertEqual(
                record["outcome_label"],
                "TRUE_SUCCESS",
            )

            self.assertTrue(
                record["verification"]["independent_of_agent_report"]
            )

    def test_aggregate_result(self):
        agent = ORACLE.OracleAgent()
        verifier = VERIFIER.IndependentVerifier()
        runner = RUNNER.PilotRunner(agent, verifier)

        evidence = runner.run(self.tasks)
        result = RUN_P1.build_summary(evidence)

        self.assertEqual(
            result["task_count"],
            len(self.tasks),
        )

        self.assertEqual(
            result["outcome_counts"]["TRUE_SUCCESS"],
            len(self.tasks),
        )

        self.assertEqual(
            result["outcome_counts"]["FALSE_SUCCESS"],
            0,
        )

        self.assertEqual(
            result["outcome_counts"]["FAILURE"],
            0,
        )

        self.assertEqual(
            result["outcome_counts"]["FALSE_FAILURE"],
            0,
        )

        self.assertEqual(result["accuracy"], 1.0)

    def test_repeated_runs_have_identical_outcomes(self):
        agent = ORACLE.OracleAgent()
        verifier = VERIFIER.IndependentVerifier()
        runner = RUNNER.PilotRunner(agent, verifier)

        first = runner.run(self.tasks)
        second = runner.run(self.tasks)

        first_projection = [
            (
                record["task_id"],
                record["expected_outcome"],
                record["observed_outcome"],
                record["outcome_label"],
                record["metrics"]["exact_match"],
            )
            for record in first
        ]

        second_projection = [
            (
                record["task_id"],
                record["expected_outcome"],
                record["observed_outcome"],
                record["outcome_label"],
                record["metrics"]["exact_match"],
            )
            for record in second
        ]

        self.assertEqual(first_projection, second_projection)


if __name__ == "__main__":
    unittest.main()
