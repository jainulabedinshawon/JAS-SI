from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.authorization import (
    ActionRequest,
    AuthorizationGate,
    AuthorizationGrant,
)


class TestAuthorizationResourceValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)

    def request(self, resource: str) -> ActionRequest:
        return ActionRequest(
            action_id="resource-test-001",
            action_type="write_file",
            resource=resource,
        )

    def grant(self, resource: str) -> AuthorizationGrant:
        return AuthorizationGrant(
            grant_id="resource-grant-001",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=(resource,),
            expires_at=self.now + timedelta(minutes=10),
        )

    def test_normal_repository_relative_path_is_allowed(self) -> None:
        resource = "src/jas_si_agent/example.py"
        decision = self.gate.evaluate(
            self.request(resource),
            grant=self.grant(resource),
            now=self.now,
        )
        self.assertIs(decision.allowed, True)
        self.assertEqual(
            decision.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )

    def test_parent_directory_traversal_is_denied(self) -> None:
        for resource in (
            "../secret.txt",
            "src/../../secret.txt",
            "src/../secret.txt",
        ):
            with self.subTest(resource=resource):
                decision = self.gate.evaluate(
                    self.request(resource),
                    grant=self.grant(resource),
                    now=self.now,
                )
                self.assertIs(decision.allowed, False)
                self.assertEqual(
                    decision.reason,
                    "UNSAFE_RESOURCE_PATH",
                )

    def test_absolute_paths_are_denied(self) -> None:
        for resource in (
            "/etc/passwd",
            "C:/Windows/system.ini",
            "//server/share/file.txt",
        ):
            with self.subTest(resource=resource):
                decision = self.gate.evaluate(
                    self.request(resource),
                    grant=self.grant(resource),
                    now=self.now,
                )
                self.assertIs(decision.allowed, False)
                self.assertEqual(
                    decision.reason,
                    "UNSAFE_RESOURCE_PATH",
                )

    def test_backslash_and_null_byte_are_denied(self) -> None:
        for resource in (
            r"src\..\secret.txt",
            "src/\x00secret.txt",
        ):
            with self.subTest(resource=repr(resource)):
                decision = self.gate.evaluate(
                    self.request(resource),
                    grant=self.grant(resource),
                    now=self.now,
                )
                self.assertIs(decision.allowed, False)
                self.assertEqual(
                    decision.reason,
                    "UNSAFE_RESOURCE_PATH",
                )

    def test_ambiguous_path_components_are_denied(self) -> None:
        for resource in (
            "src//secret.txt",
            "./README.md",
            "src/./secret.txt",
            " src/secret.txt",
            "src/secret.txt ",
            "src/*",
        ):
            with self.subTest(resource=resource):
                decision = self.gate.evaluate(
                    self.request(resource),
                    grant=self.grant(resource),
                    now=self.now,
                )
                self.assertIs(decision.allowed, False)
                self.assertEqual(
                    decision.reason,
                    "UNSAFE_RESOURCE_PATH",
                )

    def test_unsafe_resource_in_grant_is_denied(self) -> None:
        grant = self.grant("../secret.txt")
        decision = self.gate.evaluate(
            self.request("README.md"),
            grant=grant,
            now=self.now,
        )
        self.assertIs(decision.allowed, False)
        self.assertEqual(
            decision.reason,
            "INVALID_GRANT_RESOURCES",
        )


if __name__ == "__main__":
    unittest.main()
