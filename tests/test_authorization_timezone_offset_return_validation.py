
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone, tzinfo
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


class InvalidReturnTimezone(tzinfo):
    """Return an invalid type from utcoffset()."""

    def utcoffset(self, dt):
        return "not-a-timedelta"

    def dst(self, dt):
        return timedelta(0)


class TestMalformedTimezoneOffsetReturn(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()

        self.now = datetime(
            2026, 10, 24, 12, 0,
            tzinfo=timezone.utc,
        )

        self.request = ActionRequest(
            action_id="invalid-offset-001",
            action_type="write_file",
            resource="README.md",
        )

        self.grant = AuthorizationGrant(
            grant_id="invalid-offset-grant",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("README.md",),
            expires_at=self.now + timedelta(minutes=10),
        )

    def test_invalid_current_offset_type_is_denied(self) -> None:
        malformed_now = datetime(
            2026, 10, 24, 12, 0,
            tzinfo=InvalidReturnTimezone(),
        )

        decision = self.gate.evaluate(
            self.request,
            grant=self.grant,
            now=malformed_now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "INVALID_CURRENT_TIME",
        )
        self.assertEqual(
            decision.grant_id,
            self.grant.grant_id,
        )

    def test_invalid_expiry_offset_type_is_denied(self) -> None:
        malformed_expiry = datetime(
            2026, 10, 24, 18, 0,
            tzinfo=InvalidReturnTimezone(),
        )

        malformed_grant = AuthorizationGrant(
            grant_id=self.grant.grant_id,
            approved_by=self.grant.approved_by,
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("README.md",),
            expires_at=malformed_expiry,
        )

        decision = self.gate.evaluate(
            self.request,
            grant=malformed_grant,
            now=self.now,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "INVALID_GRANT_EXPIRY",
        )
        self.assertEqual(
            decision.grant_id,
            malformed_grant.grant_id,
        )


if __name__ == "__main__":
    unittest.main()
