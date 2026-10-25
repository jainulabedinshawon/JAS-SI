
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.audit_store import JsonlAuditStore
from jas_si_agent.authorization import ActionRequest
from jas_si_agent.checkpoint_store import JsonCheckpointStore
from jas_si_agent.guarded_authorization import (
    IntegrityGuardedAuthorizationService,
)


class TestIntegrityGuardedAuthorization(unittest.TestCase):
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

        self.service = IntegrityGuardedAuthorizationService(
            audit_store=self.audit,
            checkpoint_store=self.checkpoints,
        )

    def request(self, action_type: str) -> ActionRequest:
        return ActionRequest(
            action_id="test-action-001",
            action_type=action_type,
            resource="README.md",
        )

    def test_missing_checkpoint_denies_safe_action(self) -> None:
        integrity, decision = self.service.authorize(
            self.request("read_repository")
        )

        self.assertFalse(integrity.valid)
        self.assertFalse(decision.allowed)
        self.assertTrue(
            decision.reason.startswith(
                "STARTUP_INTEGRITY_CHECK_FAILED:"
            )
        )

    def test_valid_genesis_checkpoint_allows_policy_evaluation(
        self,
    ) -> None:
        self.checkpoints.create_and_save(())

        integrity, decision = self.service.authorize(
            self.request("read_repository")
        )

        self.assertTrue(integrity.valid)
        self.assertTrue(decision.allowed)
        self.assertEqual(
            decision.reason,
            "SAFE_ACTION_POLICY_ALLOWED",
        )

    def test_valid_integrity_does_not_enable_disabled_action(
        self,
    ) -> None:
        self.checkpoints.create_and_save(())

        integrity, decision = self.service.authorize(
            self.request("execute_shell")
        )

        self.assertTrue(integrity.valid)
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason,
            "ACTION_DISABLED_IN_MVP",
        )

    def test_stale_checkpoint_denies_safe_action(self) -> None:
        self.checkpoints.create_and_save(())

        # Add a record-shaped line that is not a valid audit record.
        # Invalid audit data must fail closed before authorization.
        self.audit.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        self.audit.path.write_text(
            '{"tampered": true}\n',
            encoding="utf-8",
        )

        integrity, decision = self.service.authorize(
            self.request("read_repository")
        )

        self.assertFalse(integrity.valid)
        self.assertFalse(decision.allowed)
        self.assertTrue(
            decision.reason.startswith(
                "STARTUP_INTEGRITY_CHECK_FAILED:"
            )
        )


if __name__ == "__main__":
    unittest.main()
