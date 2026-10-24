
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


class TestAuthorizationTimeBoundaryEdges(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.now = datetime(
            2026, 10, 24, 12, 0, 0,
            tzinfo=timezone.utc,
        )

        self.request = ActionRequest(
            action_id="time-edge-001",
            action_type="write_file",
            resource="README.md",
        )

    def make_grant(
        self,
        expires_at: datetime,
    ) -> AuthorizationGrant:
        return AuthorizationGrant(
            grant_id="time-edge-grant-001",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("README.md",),
            expires_at=expires_at,
        )

    def test_grant_is_denied_after_expiry(self) -> None:
        grant = self.make_grant(
            self.now - timedelta(microseconds=1)
        )

        decision = self.gate.evaluate(
            self.request,
            grant=grant,
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "GRANT_EXPIRED")
        self.assertEqual(decision.grant_id, grant.grant_id)

    def test_equivalent_timezone_instants_respect_expiry(self) -> None:
        # 12:00 UTC is the same instant as 18:00 at UTC+06:00.
        local_now = datetime(
            2026, 10, 24, 18, 0, 0,
            tzinfo=timezone(timedelta(hours=6)),
        )

        grant = self.make_grant(
            datetime(
                2026, 10, 24, 12, 0, 0,
                tzinfo=timezone.utc,
            )
        )

        decision = self.gate.evaluate(
            self.request,
            grant=grant,
            now=local_now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "GRANT_EXPIRED")

    def test_future_expiry_with_non_utc_offset_is_accepted(self) -> None:
        expiry_local = datetime(
            2026, 10, 24, 18, 10, 0,
            tzinfo=timezone(timedelta(hours=6)),
        )

        grant = self.make_grant(expiry_local)

        decision = self.gate.evaluate(
            self.request,
            grant=grant,
            now=self.now,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )

    def test_naive_expiry_is_denied(self) -> None:
        naive_expiry = datetime(2026, 10, 24, 18, 10, 0)
        grant = self.make_grant(naive_expiry)

        decision = self.gate.evaluate(
            self.request,
            grant=grant,
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "TIMEZONE_REQUIRED")


if __name__ == "__main__":
    unittest.main()
