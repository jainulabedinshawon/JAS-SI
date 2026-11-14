from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OracleResult:
    reported_status: str
    reported_outcome: str
    observed_outcome: str


class OracleAgent:
    """
    Deterministic reference agent for the P1 apparatus test only.

    P1 fixtures currently define one fixed expected outcome. The oracle
    emits that fixed apparatus response; it never reads evaluator ground
    truth. This is not an intelligence-performance baseline.
    """

    CONDITION = "P1_ORACLE"
    APPARATUS_OUTCOME = "P1_DETERMINISTIC_SUCCESS"

    def run(self, task: dict) -> OracleResult:
        if not isinstance(task, dict):
            raise TypeError("task must be a dictionary")

        task_id = task.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("task_id must be a non-empty string")

        if "ground_truth" in task or "expected_outcome" in task:
            raise ValueError("Evaluator-only ground truth must not be agent-visible")

        return OracleResult(
            reported_status="SUCCESS",
            reported_outcome=self.APPARATUS_OUTCOME,
            observed_outcome=self.APPARATUS_OUTCOME,
        )
