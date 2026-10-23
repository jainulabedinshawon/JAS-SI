
from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.audit_store import JsonlAuditStore
from jas_si_agent.authorization import (
    ActionRequest,
    AuthorizationGrant,
)
from jas_si_agent.checkpoint_store import JsonCheckpointStore
from jas_si_agent.guarded_authorization import (
    IntegrityGuardedAuthorizationService,
)


class TestGuardedAuthorizationAdversarial(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        root = Path(self.temp_dir.name)
        self.audit = JsonlAuditStore(
            root / "audit" / "events.jsonl"
        )
        self.checkpoints = JsonCheckpointStore(
            root / "checkpoints" / "audit.json"
        )
        self.checkpoints.create_and_save(())

        self.service = IntegrityGuardedAuthorizationService(
            self.audit,
            self.checkpoints,
        )

    def request(
        self,
        action_type: str = "read_repository",
        resource: str = "README.md",
    ) -> ActionRequest:
        return ActionRequest(
            action_id="adversarial-001",
            action_type=action_type,
            resource=resource,
        )

    def test_none_request_is_denied(self) -> None:
        integrity, decision = self.service.authorize(None)  # type: ignore[arg-type]

        self.assertTrue(integrity.valid)
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "INVALID_ACTION_REQUEST",
        )

    def test_expired_human_grant_is_denied(self) -> None:
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="grant-expired",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("README.md",),
            expires_at=now - timedelta(seconds=1),
        )

        integrity, decision = self.service.authorize(
            self.request("write_file"),
            grant=grant,
            now=now,
        )

        self.assertTrue(integrity.valid)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "GRANT_EXPIRED")

    def test_wildcard_resource_is_denied(self) -> None:
        integrity, decision = self.service.authorize(
            self.request(resource="*")
        )

        self.assertTrue(integrity.valid)
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "WILDCARD_RESOURCE_NOT_ALLOWED",
        )

    def test_write_without_grant_is_denied(self) -> None:
        integrity, decision = self.service.authorize(
            self.request("write_file")
        )

        self.assertTrue(integrity.valid)
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "HUMAN_APPROVAL_REQUIRED",
        )

    def test_unexpected_integrity_error_denies_request(self) -> None:
        with patch(
            "jas_si_agent.guarded_authorization.verify_startup_integrity",
            side_effect=RuntimeError("simulated integrity failure"),
        ):
            integrity, decision = self.service.authorize(
                self.request()
            )

        self.assertFalse(integrity.valid)
        self.assertEqual(
            integrity.reason,
            "UNEXPECTED_INTEGRITY_CHECK_ERROR",
        )
        self.assertFalse(decision.allowed)
        self.assertTrue(
            decision.reason.startswith(
                "STARTUP_INTEGRITY_CHECK_FAILED:"
            )
        )

    def test_shell_remains_disabled(self) -> None:
        integrity, decision = self.service.authorize(
            self.request("execute_shell")
        )

        self.assertTrue(integrity.valid)
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "ACTION_DISABLED_IN_MVP",
        )

    def test_corrupted_audit_log_denies_request(self) -> None:
        self.audit.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        self.audit.path.write_text(
            "this is not valid JSON\n",
            encoding="utf-8",
        )

        integrity, decision = self.service.authorize(
            self.request()
        )

        self.assertFalse(integrity.valid)
        self.assertEqual(
            integrity.reason,
            "AUDIT_LOG_INVALID_OR_UNREADABLE",
        )
        self.assertFalse(decision.allowed)
        self.assertTrue(
            decision.reason.startswith(
                "STARTUP_INTEGRITY_CHECK_FAILED:"
            )
        )

    def test_authorization_evaluator_error_denies_request(
        self,
    ) -> None:
        with patch.object(
            self.service._authorization_gate,
            "evaluate",
            side_effect=RuntimeError(
                "simulated authorization failure"
            ),
        ):
            integrity, decision = self.service.authorize(
                self.request()
            )

        self.assertTrue(integrity.valid)
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "AUTHORIZATION_EVALUATION_ERROR",
        )
        self.assertEqual(
            decision.action_id,
            "adversarial-001",
        )

    def test_malformed_action_type_is_denied(self) -> None:
        malformed_request = ActionRequest(
            action_id="adversarial-002",
            action_type=None,  # type: ignore[arg-type]
            resource="README.md",
        )

        integrity, decision = self.service.authorize(
            malformed_request
        )

        self.assertTrue(integrity.valid)
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "INVALID_ACTION_TYPE",
        )
        self.assertEqual(
            decision.action_id,
            "adversarial-002",
        )

if __name__ == "__main__":
    unittest.main()
