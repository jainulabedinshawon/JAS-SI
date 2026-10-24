
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.authorization import (
    ActionRequest,
    AuthorizationGate,
)


class TestAuthorizationRequestValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()

    def evaluate(self, request: object):
        return self.gate.evaluate(
            request,  # type: ignore[arg-type]
        )

    def test_non_request_object_is_denied(self) -> None:
        for request in (None, object(), {}, "request"):
            with self.subTest(request_type=type(request).__name__):
                decision = self.evaluate(request)

                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    "INVALID_ACTION_REQUEST",
                )

    def test_non_string_action_ids_are_denied(self) -> None:
        for action_id in (None, 123, [], {}):
            with self.subTest(action_id_type=type(action_id).__name__):
                request = ActionRequest(
                    action_id=action_id,  # type: ignore[arg-type]
                    action_type="read_repository",
                    resource="README.md",
                )

                decision = self.evaluate(request)

                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    "INVALID_ACTION_ID",
                )

    def test_blank_action_ids_are_denied(self) -> None:
        for action_id in ("", " ", "\t", "\n"):
            with self.subTest(action_id=repr(action_id)):
                request = ActionRequest(
                    action_id=action_id,
                    action_type="read_repository",
                    resource="README.md",
                )

                decision = self.evaluate(request)

                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    "INVALID_ACTION_ID",
                )

    def test_non_string_action_types_are_denied(self) -> None:
        for action_type in (None, 123, [], {}):
            with self.subTest(
                action_type_type=type(action_type).__name__
            ):
                request = ActionRequest(
                    action_id="request-validation-001",
                    action_type=action_type,  # type: ignore[arg-type]
                    resource="README.md",
                )

                decision = self.evaluate(request)

                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    "INVALID_ACTION_TYPE",
                )

    def test_non_string_resources_are_denied(self) -> None:
        for resource in (None, 123, [], {}):
            with self.subTest(
                resource_type=type(resource).__name__
            ):
                request = ActionRequest(
                    action_id="request-validation-002",
                    action_type="read_repository",
                    resource=resource,  # type: ignore[arg-type]
                )

                decision = self.evaluate(request)

                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    "INVALID_RESOURCE",
                )

    def test_blank_resources_are_denied(self) -> None:
        for resource in ("", " ", "\t", "\n"):
            with self.subTest(resource=repr(resource)):
                request = ActionRequest(
                    action_id="request-validation-003",
                    action_type="read_repository",
                    resource=resource,
                )

                decision = self.evaluate(request)

                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    "EMPTY_RESOURCE",
                )

    def test_whitespace_padded_wildcard_is_denied(self) -> None:
        for resource in ("*", " * ", "\t*\n"):
            with self.subTest(resource=repr(resource)):
                request = ActionRequest(
                    action_id="request-validation-004",
                    action_type="write_file",
                    resource=resource,
                )

                decision = self.evaluate(request)

                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    "WILDCARD_RESOURCE_NOT_ALLOWED",
                )

    def test_unknown_action_type_is_denied(self) -> None:
        request = ActionRequest(
            action_id="request-validation-005",
            action_type="unregistered_action",
            resource="README.md",
        )

        decision = self.evaluate(request)

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "UNKNOWN_ACTION_TYPE",
        )


if __name__ == "__main__":
    unittest.main()
