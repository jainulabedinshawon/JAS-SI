from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OracleResult:
    reported_status: str
    reported_outcome: str
    observed_outcome: str


class OracleAgent:
    """
    Deterministic reference agent.

    This agent is not an intelligence-performance baseline.
    It exists only to test the pilot apparatus.
    """

    CONDITION = "P1_ORACLE"

    def run(self, task: dict) -> OracleResult:
        if not isinstance(task, dict):
            raise TypeError("task must be a dictionary")

        task_id = task.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("task_id must be a non-empty string")

        ground_truth = task.get("ground_truth")
        if not isinstance(ground_truth, dict):
            raise ValueError("ground_truth must be an object")

        expected_outcome = ground_truth.get("expected_outcome")
        if not isinstance(expected_outcome, str) or not expected_outcome:
            raise ValueError(
                "ground_truth.expected_outcome must be a non-empty string"
            )

        return OracleResult(
            reported_status="SUCCESS",
            reported_outcome=expected_outcome,
            observed_outcome=expected_outcome,
        )
