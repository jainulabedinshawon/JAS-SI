
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.audit_log import AuditLog  # noqa: E402
from jas_si_agent.authorization import (  # noqa: E402
    ActionRequest,
    AuthorizationDecision,
)
from jas_si_agent.verification import (  # noqa: E402
    VerificationResult,
    VerificationStatus,
)


class TestAuditGrantIdValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.log = AuditLog()

        self.request = ActionRequest(
            action_id="grant-validation-001",
            action_type="write_file",
            resource="README.md",
        )

        self.verification = VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            reason="NO_ACTION_EXECUTION_PERFORMED",
            action_id="grant-validation-001",
        )

    def decision(
        self,
        grant_id: object = None,
    ) -> AuthorizationDecision:
        return AuthorizationDecision(
            allowed=False,
            reason="TEST_DENIAL",
            action_id="grant-validation-001",
            grant_id=grant_id,
        )

    def test_none_grant_id_is_accepted(self) -> None:
        record = self.log.append(
            self.request,
            self.decision(),
            self.verification,
        )

        self.assertIsNone(record.grant_id)
        self.assertTrue(self.log.verify_integrity())

    def test_nonempty_grant_id_is_preserved(self) -> None:
        record = self.log.append(
            self.request,
            self.decision("human-grant-001"),
            self.verification,
        )

        self.assertEqual(record.grant_id, "human-grant-001")
        self.assertTrue(self.log.verify_integrity())

    def test_empty_grant_id_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.log.append(
                self.request,
                self.decision(""),
                self.verification,
            )

        self.assertEqual(len(self.log.records), 0)
        self.assertTrue(self.log.verify_integrity())

    def test_whitespace_grant_id_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.log.append(
                self.request,
                self.decision("   "),
                self.verification,
            )

        self.assertEqual(len(self.log.records), 0)
        self.assertTrue(self.log.verify_integrity())

    def test_non_string_grant_id_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            self.log.append(
                self.request,
                self.decision(123),
                self.verification,
            )

        self.assertEqual(len(self.log.records), 0)
        self.assertTrue(self.log.verify_integrity())


if __name__ == "__main__":
    unittest.main()
