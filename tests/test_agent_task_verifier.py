from __future__ import annotations

import unittest
import uuid
from unittest.mock import Mock, patch

from jas_si_agent.agent_task_verifier import AgentTaskVerifier
from jas_si_agent.github_task_verifier import (
    PersistedTask,
    TaskVerificationDecision,
    WorkerTaskReport,
)
from jas_si_agent.verification import VerificationStatus


TASK_ID = uuid.UUID("00000000-0000-0000-0000-000000000051")
TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000052")


def make_item():
    task = PersistedTask(
        task_id=TASK_ID,
        tenant_id=TENANT_ID,
        task_type="github.read_repository",
        verifier_claim_token=uuid.UUID("00000000-0000-0000-0000-000000000053"),
        input_payload={
            "repository": "owner/project",
            "commit_sha": "a" * 40,
            "paths": ["README.md"],
        },
    )
    report = WorkerTaskReport(
        task_id=TASK_ID,
        claimed_success=True,
        result_payload={
            "task_type": "github.read_repository",
            "repository": "owner/project",
            "commit_sha": "a" * 40,
        },
    )
    return task, report


def make_decision(status=VerificationStatus.VERIFIED_SUCCESS):
    return TaskVerificationDecision(
        status=status,
        reason="test",
        task_id=TASK_ID,
        evidence=None,
    )


class AgentTaskVerifierTests(unittest.TestCase):
    def make_verifier(self, store, collector=None):
        return AgentTaskVerifier(
            store=store,
            collector=collector or Mock(),
            batch_size=4,
        )

    def test_verified_success_is_finalized(self):
        store = Mock()
        store.claim_awaiting_verification.return_value = [make_item()]
        store.finalize_success.return_value = True
        collector = Mock()
        decision = make_decision()

        with patch(
            "jas_si_agent.agent_task_verifier.verify_github_repository_task",
            return_value=decision,
        ) as verify:
            result = self.make_verifier(store, collector).run_once()

        verify.assert_called_once()
        store.claim_awaiting_verification.assert_called_once_with(limit=4, lease_seconds=120)
        store.finalize_success.assert_called_once()
        store.release_claim.assert_not_called()
        self.assertEqual(result.scanned, 1)
        self.assertEqual(result.finalized, 1)
        self.assertEqual(result.inconclusive, 0)
        self.assertEqual(result.lost_finalization_race, 0)

    def test_inconclusive_result_remains_pending(self):
        store = Mock()
        store.claim_awaiting_verification.return_value = [make_item()]

        with patch(
            "jas_si_agent.agent_task_verifier.verify_github_repository_task",
            return_value=make_decision(VerificationStatus.INCONCLUSIVE),
        ):
            result = self.make_verifier(store).run_once()

        store.finalize_success.assert_not_called()
        # Keep the claim until its 120-second lease expires so the supervisor
        # cannot hot-loop on permanently inconclusive evidence.
        store.release_claim.assert_not_called()
        self.assertEqual(result.scanned, 1)
        self.assertEqual(result.finalized, 0)
        self.assertEqual(result.inconclusive, 1)

    def test_verification_exception_keeps_claim_until_lease_expiry(self):
        store = Mock()
        store.claim_awaiting_verification.return_value = [make_item()]

        with patch(
            "jas_si_agent.agent_task_verifier.verify_github_repository_task",
            side_effect=RuntimeError("collector unavailable"),
        ):
            with self.assertRaisesRegex(RuntimeError, "collector unavailable"):
                self.make_verifier(store).run_once()

        store.finalize_success.assert_not_called()
        store.release_claim.assert_not_called()

    def test_stale_task_finalization_is_counted_as_lost_race(self):
        store = Mock()
        store.claim_awaiting_verification.return_value = [make_item()]
        store.finalize_success.return_value = False

        with patch(
            "jas_si_agent.agent_task_verifier.verify_github_repository_task",
            return_value=make_decision(),
        ):
            result = self.make_verifier(store).run_once()

        self.assertEqual(result.finalized, 0)
        self.assertEqual(result.lost_finalization_race, 1)
        store.release_claim.assert_called_once()

    def test_empty_queue_is_a_noop(self):
        store = Mock()
        store.claim_awaiting_verification.return_value = []

        result = self.make_verifier(store).run_once()

        self.assertEqual(
            result,
            type(result)(scanned=0, finalized=0, inconclusive=0, lost_finalization_race=0),
        )
        store.finalize_success.assert_not_called()

    def test_batch_size_is_bounded(self):
        store = Mock()
        collector = Mock()
        for size in (0, 21, True, 1.5):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    AgentTaskVerifier(store=store, collector=collector, batch_size=size)


if __name__ == "__main__":
    unittest.main()
