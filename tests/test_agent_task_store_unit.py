"""Unit tests for bounded and canonical task-store request validation."""

import unittest

from jas_si_agent.agent_task_store import (
    AgentTaskIdempotencyConflict,
    AgentTaskStoreError,
    PostgresAgentTaskStore,
)


class TestAgentTaskStoreValidation(unittest.TestCase):
    def setUp(self):
        self.store = PostgresAgentTaskStore("postgresql://test-only")

    def valid(self):
        return dict(
            idempotency_key="request-1",
            task_type="research",
            input_payload={"question": "evidence"},
            max_attempts=3,
        )

    def test_rejects_empty_dsn(self):
        with self.assertRaises(ValueError):
            PostgresAgentTaskStore(" ")

    def test_normalizes_json_and_produces_digest(self):
        payload, digest = self.store._validate_request(**self.valid())
        self.assertEqual(payload, {"question": "evidence"})
        self.assertEqual(len(digest), 32)

    def test_idempotency_key_is_bounded_and_ascii_safe(self):
        for value in ("", "white space", "x" * 129, "💥"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.store._validate_request(**{**self.valid(), "idempotency_key": value})

    def test_task_type_and_attempts_are_bounded(self):
        for task_type in ("", " " * 2, "x" * 65):
            with self.subTest(task_type=task_type), self.assertRaises(ValueError):
                self.store._validate_request(**{**self.valid(), "task_type": task_type})
        for attempts in (0, 11, True, 1.5):
            with self.subTest(attempts=attempts), self.assertRaises(ValueError):
                self.store._validate_request(**{**self.valid(), "max_attempts": attempts})

    def test_rejects_non_mapping_and_non_finite_json(self):
        for payload in (None, [], {"value": float("nan")}, {"value": object()}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.store._validate_request(**{**self.valid(), "input_payload": payload})

    def test_rejects_payload_over_64_kib(self):
        with self.assertRaises(ValueError):
            self.store._validate_request(**{**self.valid(), "input_payload": {"x": "a" * 70000}})


if __name__ == "__main__":
    unittest.main()
