
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


class TestAuthorizationGrantBoundaries(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(
            2026, 10, 24, 12, 0, 0,
            tzinfo=timezone.utc,
        )

    def request(self, resource: str = "README.md") -> ActionRequest:
        return ActionRequest(
            action_id="grant-boundary-001",
            action_type="write_file",
            resource=resource,
        )

    def grant(
        self,
        *,
        grant_id: str = "grant-boundary-001",
        approved_by: str = "human-reviewer",
        resources: tuple[str, ...] = ("README.md",),
        expires_at: datetime | None = None,
    ) -> AuthorizationGrant:
        return AuthorizationGrant(
            grant_id=grant_id,
            approved_by=approved_by,
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=resources,
            expires_at=(
                expires_at
                if expires_at is not None
                else self.now + timedelta(minutes=10)
            ),
        )

    def test_grant_expiring_one_microsecond_later_is_accepted(
        self,
    ) -> None:
        grant = self.grant(
            expires_at=self.now + timedelta(microseconds=1),
        )

        decision = self.gate.evaluate(
            self.request(),
            grant=grant,
            now=self.now,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )

    def test_grant_expiring_at_current_time_is_denied(self) -> None:
        grant = self.grant(expires_at=self.now)

        decision = self.gate.evaluate(
            self.request(),
            grant=grant,
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "GRANT_EXPIRED")

    def test_naive_current_time_is_denied(self) -> None:
        grant = self.grant()
        naive_now = datetime(2026, 10, 24, 12, 0, 0)

        decision = self.gate.evaluate(
            self.request(),
            grant=grant,
            now=naive_now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "TIMEZONE_REQUIRED")

    def test_blank_grant_id_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(grant_id="   "),
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "INVALID_GRANT_ID")

    def test_blank_approver_is_denied(self) -> None:
        decision = self.gate.evaluate(
            self.request(),
            grant=self.grant(approved_by="   "),
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "MISSING_APPROVER")

    def test_wildcard_grant_does_not_authorize_named_resource(
        self,
    ) -> None:
        grant = self.grant(resources=("*",))

        decision = self.gate.evaluate(
            self.request(resource="README.md"),
            grant=grant,
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "RESOURCE_OUTSIDE_GRANT_SCOPE",
        )


if __name__ == "__main__":
    unittest.main()
