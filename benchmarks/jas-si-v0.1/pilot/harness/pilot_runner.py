from __future__ import annotations

from datetime import datetime, timezone


class PilotRunner:
    """
    Minimal deterministic execution harness.

    The harness coordinates:
        Agent -> Observation -> Independent Verification -> Evidence
    """

    SCHEMA_VERSION = "0.1.0"

    def __init__(self, agent, verifier):
        self.agent = agent
        self.verifier = verifier

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    def run_task(self, task: dict) -> dict:
        if not isinstance(task, dict):
            raise TypeError("task must be a dictionary")

        task_id = task.get("task_id")
        ground_truth = task.get("ground_truth")

        if not isinstance(task_id, str) or not task_id:
            raise ValueError("task_id must be a non-empty string")

        if not isinstance(ground_truth, dict):
            raise ValueError("ground_truth must be an object")

        expected_outcome = ground_truth.get("expected_outcome")

        if not isinstance(expected_outcome, str) or not expected_outcome:
            raise ValueError(
                "ground_truth.expected_outcome must be a non-empty string"
            )

        agent_result = self.agent.run(task)

        verification = self.verifier.verify(
            expected_outcome=expected_outcome,
            observed_outcome=agent_result.observed_outcome,
            reported_status=agent_result.reported_status,
        )

        return {
            "schema_version": self.SCHEMA_VERSION,
            "task_id": task_id,
            "agent_condition": self.agent.CONDITION,
            "expected_outcome": expected_outcome,
            "observed_outcome": agent_result.observed_outcome,
            "agent_report": {
                "reported_status": agent_result.reported_status,
                "reported_outcome": agent_result.reported_outcome,
            },
            "verification": {
                "verified": verification.verified,
                "verification_basis": verification.verification_basis,
                "independent_of_agent_report": (
                    verification.independent_of_agent_report
                ),
            },
            "outcome_label": verification.outcome_label,
            "metrics": {
                "exact_match": verification.exact_match,
            },
            "timestamp": self._timestamp(),
        }

    def run(self, tasks: list[dict]) -> list[dict]:
        if not isinstance(tasks, list):
            raise TypeError("tasks must be a list")

        return [self.run_task(task) for task in tasks]
