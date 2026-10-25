
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.audit_log import AuditLog
from jas_si_agent.authorization import (
    ActionRequest,
    AuthorizationGate,
    AuthorizationGrant,
)
from jas_si_agent.verification import (
    VerificationResult,
    VerificationStatus,
)


class TestAuthorizationDenialMatrix(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.audit_log = AuditLog()
        self.now = datetime(
            2026, 10, 25, 12, 0, 0,
            tzinfo=timezone.utc,
        )

    def make_request(
        self,
        *,
        action_id: str,
        action_type: str = "write_file",
        resource: str = "README.md",
    ) -> ActionRequest:
        return ActionRequest(
            action_id=action_id,
            action_type=action_type,
            resource=resource,
        )

    def make_grant(
        self,
        *,
        grant_id: str = "denial-matrix-grant",
        human_approved: bool = True,
        allowed_actions: tuple[str, ...] = ("write_file",),
        allowed_resources: tuple[str, ...] = ("README.md",),
        expires_at: datetime | None = None,
    ) -> AuthorizationGrant:
        return AuthorizationGrant(
            grant_id=grant_id,
            approved_by="human-reviewer",
            human_approved=human_approved,
            allowed_actions=allowed_actions,
            allowed_resources=allowed_resources,
            expires_at=(
                expires_at
                if expires_at is not None
                else self.now + timedelta(minutes=10)
            ),
        )

    def evaluate_and_audit(
        self,
        request: ActionRequest,
        grant: AuthorizationGrant,
    ):
        decision = self.gate.evaluate(
            request,
            grant=grant,
            now=self.now,
        )

        # No action is executed; real-world outcome remains unknown.
        verification = VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            reason="NO_ACTION_EXECUTION_PERFORMED",
            action_id=request.action_id,
        )

        record = self.audit_log.append(
            request,
            decision,
            verification,
        )

        return decision, record

    def assert_denied_and_audited(
        self,
        *,
        request: ActionRequest,
        grant: AuthorizationGrant,
        expected_reason: str,
    ) -> None:
        decision, record = self.evaluate_and_audit(
            request,
            grant,
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, expected_reason)

        self.assertFalse(record.authorized)
        self.assertEqual(
            record.authorization_reason,
            expected_reason,
        )
        self.assertEqual(
            record.action_id,
            request.action_id,
        )
        self.assertEqual(
            record.verification_status,
            "INCONCLUSIVE",
        )
        self.assertTrue(self.audit_log.verify_integrity())

    def test_expired_grant_is_denied_and_audited(self) -> None:
        request = self.make_request(
            action_id="denial-expired-001",
        )
        grant = self.make_grant(
            expires_at=self.now,
        )

        self.assert_denied_and_audited(
            request=request,
            grant=grant,
            expected_reason="GRANT_EXPIRED",
        )

    def test_action_outside_grant_scope_is_denied(self) -> None:
        request = self.make_request(
            action_id="denial-action-scope-001",
            action_type="write_file",
        )
        grant = self.make_grant(
            allowed_actions=("create_pull_request",),
        )

        self.assert_denied_and_audited(
            request=request,
            grant=grant,
            expected_reason="ACTION_OUTSIDE_GRANT_SCOPE",
        )

    def test_resource_outside_grant_scope_is_denied(self) -> None:
        request = self.make_request(
            action_id="denial-resource-scope-001",
            resource="src/private.py",
        )
        grant = self.make_grant(
            allowed_resources=("README.md",),
        )

        self.assert_denied_and_audited(
            request=request,
            grant=grant,
            expected_reason="RESOURCE_OUTSIDE_GRANT_SCOPE",
        )

    def test_unconfirmed_human_approval_is_denied(self) -> None:
        request = self.make_request(
            action_id="denial-human-approval-001",
        )
        grant = self.make_grant(
            human_approved=False,
        )

        self.assert_denied_and_audited(
            request=request,
            grant=grant,
            expected_reason="HUMAN_APPROVAL_NOT_CONFIRMED",
        )

    def test_denial_matrix_preserves_hash_chain(self) -> None:
        cases = (
            (
                "matrix-expired-001",
                self.make_grant(expires_at=self.now),
                "GRANT_EXPIRED",
            ),
            (
                "matrix-action-scope-001",
                self.make_grant(
                    allowed_actions=("create_pull_request",),
                ),
                "ACTION_OUTSIDE_GRANT_SCOPE",
            ),
            (
                "matrix-resource-scope-001",
                self.make_grant(
                    allowed_resources=("src/private.py",),
                ),
                "RESOURCE_OUTSIDE_GRANT_SCOPE",
            ),
            (
                "matrix-unapproved-001",
                self.make_grant(human_approved=False),
                "HUMAN_APPROVAL_NOT_CONFIRMED",
            ),
        )

        for action_id, grant, expected_reason in cases:
            with self.subTest(
                action_id=action_id,
                expected_reason=expected_reason,
            ):
                request = self.make_request(
                    action_id=action_id,
                )

                decision, record = self.evaluate_and_audit(
                    request,
                    grant,
                )

                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    expected_reason,
                )
                self.assertFalse(record.authorized)
                self.assertEqual(
                    record.authorization_reason,
                    expected_reason,
                )

        records = self.audit_log.records
        self.assertEqual(len(records), 4)
        self.assertEqual(
            [record.sequence for record in records],
            [1, 2, 3, 4],
        )

        for previous, current in zip(records, records[1:]):
            self.assertEqual(
                current.previous_hash,
                previous.record_hash,
            )

        self.assertTrue(self.audit_log.verify_integrity())


if __name__ == "__main__":
    unittest.main()
