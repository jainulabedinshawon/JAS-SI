from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.audit_log import AuditLog  # noqa: E402
from jas_si_agent.authorization import (  # noqa: E402
    ActionRequest,
    AuthorizationDecision,
    AuthorizationGate,
    AuthorizationGrant,
)
from jas_si_agent.verification import (  # noqa: E402
    VerificationResult,
    VerificationStatus,
)


class TestAuthorizationAuditIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = AuthorizationGate()
        self.audit_log = AuditLog()
        self.now = datetime(
            2026, 10, 25, 12, 0, 0,
            tzinfo=timezone.utc,
        )

    def request(
        self,
        *,
        action_id: str = "integration-action-001",
        action_type: str = "write_file",
        resource: str = "README.md",
    ) -> ActionRequest:
        return ActionRequest(
            action_id=action_id,
            action_type=action_type,
            resource=resource,
        )

    def grant(
        self,
        *,
        action_type: str = "write_file",
        resource: str = "README.md",
        expires_at: datetime | None = None,
    ) -> AuthorizationGrant:
        return AuthorizationGrant(
            grant_id="integration-grant-001",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=(action_type,),
            allowed_resources=(resource,),
            expires_at=(
                expires_at
                if expires_at is not None
                else self.now + timedelta(minutes=10)
            ),
        )

    def inconclusive_result(
        self,
        action_id: str,
    ) -> VerificationResult:
        # No real action is executed in these integration tests.
        # Therefore execution success cannot be claimed.
        return VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            reason="NO_ACTION_EXECUTION_PERFORMED",
            action_id=action_id,
        )

    def evaluate_and_audit(
        self,
        request: ActionRequest,
        grant: AuthorizationGrant | None = None,
    ):
        decision = self.gate.evaluate(
            request,
            grant=grant,
            now=self.now,
        )

        record = self.audit_log.append(
            request,
            decision,
            self.inconclusive_result(request.action_id),
        )

        return decision, record

    def test_policy_allowed_decision_is_audited(self) -> None:
        request = self.request(
            action_type="read_repository",
        )

        decision, record = self.evaluate_and_audit(request)

        self.assertTrue(decision.allowed)
        self.assertTrue(record.authorized)
        self.assertEqual(
            record.authorization_reason,
            "SAFE_ACTION_POLICY_ALLOWED",
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

    def test_missing_human_grant_is_audited_as_denied(self) -> None:
        request = self.request()

        decision, record = self.evaluate_and_audit(request)

        self.assertFalse(decision.allowed)
        self.assertFalse(record.authorized)
        self.assertEqual(
            record.authorization_reason,
            "HUMAN_APPROVAL_REQUIRED",
        )
        self.assertEqual(
            record.verification_status,
            "INCONCLUSIVE",
        )
        self.assertTrue(self.audit_log.verify_integrity())

    def test_valid_scoped_grant_is_audited(self) -> None:
        request = self.request()
        grant = self.grant()

        decision, record = self.evaluate_and_audit(
            request,
            grant=grant,
        )

        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )
        self.assertTrue(record.authorized)
        self.assertEqual(
            record.authorization_reason,
            "EXPLICIT_HUMAN_GRANT_ACCEPTED",
        )
        self.assertTrue(self.audit_log.verify_integrity())

    def test_never_allowed_action_is_audited_as_denied(
        self,
    ) -> None:
        request = self.request(
            action_type="execute_shell",
        )
        grant = self.grant(action_type="execute_shell")

        decision, record = self.evaluate_and_audit(
            request,
            grant=grant,
        )

        self.assertFalse(decision.allowed)
        self.assertFalse(record.authorized)
        self.assertEqual(
            record.authorization_reason,
            "ACTION_DISABLED_IN_MVP",
        )
        self.assertTrue(self.audit_log.verify_integrity())

    def test_multiple_decisions_form_a_valid_hash_chain(
        self,
    ) -> None:
        cases = (
            (
                self.request(
                    action_id="integration-read-001",
                    action_type="read_repository",
                ),
                None,
            ),
            (
                self.request(
                    action_id="integration-write-denied-001",
                    action_type="write_file",
                ),
                None,
            ),
            (
                self.request(
                    action_id="integration-write-approved-001",
                    action_type="write_file",
                ),
                self.grant(),
            ),
            (
                self.request(
                    action_id="integration-shell-denied-001",
                    action_type="execute_shell",
                ),
                self.grant(action_type="execute_shell"),
            ),
        )

        decisions = []

        for request, grant in cases:
            decision, record = self.evaluate_and_audit(
                request,
                grant=grant,
            )
            decisions.append(decision)

            self.assertEqual(record.action_id, request.action_id)

        records = self.audit_log.records

        self.assertEqual(len(records), 4)
        self.assertEqual(
            [record.sequence for record in records],
            [1, 2, 3, 4],
        )

        for index in range(1, len(records)):
            self.assertEqual(
                records[index].previous_hash,
                records[index - 1].record_hash,
            )

        self.assertEqual(
            [decision.allowed for decision in decisions],
            [True, False, True, False],
        )
        self.assertTrue(self.audit_log.verify_integrity())

    def test_denied_action_is_never_recorded_as_authorized(
        self,
    ) -> None:
        request = self.request(
            action_type="merge_pull_request",
        )
        grant = self.grant(action_type="merge_pull_request")

        decision, record = self.evaluate_and_audit(
            request,
            grant=grant,
        )

        self.assertFalse(decision.allowed)
        self.assertFalse(record.authorized)
        self.assertEqual(
            record.authorization_reason,
            "ACTION_DISABLED_IN_MVP",
        )

    def test_authorization_reason_tampering_is_detected(
        self,
    ) -> None:
        request = self.request(
            action_type="read_repository",
        )

        _, original = self.evaluate_and_audit(request)

        self.audit_log._records[0] = replace(
            original,
            authorization_reason="ALTERED_DECISION",
        )

        self.assertFalse(self.audit_log.verify_integrity())

    def test_action_id_mismatch_prevents_audit_append(self) -> None:
        request = self.request()

        decision = AuthorizationDecision(
            allowed=False,
            reason="TEST_DENIAL",
            action_id=request.action_id,
        )

        mismatched_result = VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            reason="TEST_ONLY",
            action_id="different-action-id",
        )

        with self.assertRaises(ValueError):
            self.audit_log.append(
                request,
                decision,
                mismatched_result,
            )

        self.assertEqual(len(self.audit_log.records), 0)
        self.assertTrue(self.audit_log.verify_integrity())

    def test_checkpoint_matches_audited_chain(self) -> None:
        first_request = self.request(
            action_id="integration-checkpoint-001",
            action_type="read_repository",
        )
        self.evaluate_and_audit(first_request)

        checkpoint = self.audit_log.create_checkpoint()

        second_request = self.request(
            action_id="integration-checkpoint-002",
            action_type="write_file",
        )
        self.evaluate_and_audit(
            second_request,
            grant=self.grant(),
        )

        self.assertEqual(checkpoint.sequence, 1)
        self.assertTrue(
            self.audit_log.verify_integrity(
                checkpoint=checkpoint,
            )
        )


if __name__ == "__main__":
    unittest.main()
