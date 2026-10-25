
from __future__ import annotations

import sys
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.authorization import (
    ActionRequest,
    AuthorizationDecision,
    AuthorizationGrant,
)


class TestAuthorizationInputImmutability(unittest.TestCase):
    def setUp(self) -> None:
        self.request = ActionRequest(
            action_id="immutability-request-001",
            action_type="write_file",
            resource="README.md",
        )

        self.grant = AuthorizationGrant(
            grant_id="immutability-grant-001",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("README.md",),
            expires_at=(
                datetime.now(timezone.utc)
                + timedelta(minutes=10)
            ),
        )

        self.decision = AuthorizationDecision(
            allowed=False,
            reason="HUMAN_APPROVAL_REQUIRED",
            action_id=self.request.action_id,
        )

    def test_action_id_cannot_be_changed(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.request.action_id = "different-action"  # type: ignore[misc]

    def test_action_type_cannot_be_changed(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.request.action_type = "read_repository"  # type: ignore[misc]

    def test_resource_cannot_be_changed(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.request.resource = "another-file.txt"  # type: ignore[misc]

    def test_grant_approval_cannot_be_changed(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.grant.human_approved = False  # type: ignore[misc]

    def test_grant_scope_cannot_be_reassigned(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.grant.allowed_resources = ("*",)  # type: ignore[misc]

    def test_grant_expiry_cannot_be_changed(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.grant.expires_at = datetime.now(timezone.utc) + timedelta(days=365)  # type: ignore[misc]

    def test_decision_cannot_be_changed_to_allowed(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.decision.allowed = True  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
