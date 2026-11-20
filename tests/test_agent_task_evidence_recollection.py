from __future__ import annotations

import unittest
import uuid
from unittest.mock import Mock, patch

from jas_si_agent.agent_task_evidence_recollection import AgentTaskEvidenceRecollector
from jas_si_agent.github_task_verifier import PersistedTask, TaskVerificationDecision, WorkerTaskReport
from jas_si_agent.verification import VerificationStatus


TASK_ID = uuid.UUID("00000000-0000-0000-0000-000000000061")
TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000062")
REQUEST_ID = uuid.UUID("00000000-0000-0000-0000-000000000063")
CLAIM_TOKEN = uuid.UUID("00000000-0000-0000-0000-000000000064")


def claimed_request():
    task = PersistedTask(
        task_id=TASK_ID,
        tenant_id=TENANT_ID,
        task_type="github.read_repository",
        input_payload={
            "repository": "owner/project",
            "commit_sha": "a" * 40,
            "paths": ["README.md"],
        },
        verifier_claim_token=CLAIM_TOKEN,
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
    return REQUEST_ID, task, report


class AgentTaskEvidenceRecollectorTests(unittest.TestCase):
    def test_verified_evidence_finalizes_only_the_evidence_request(self):
        store, collector = Mock(), Mock()
        store.claim_pending.return_value = [claimed_request()]
        decision = TaskVerificationDecision(
            status=VerificationStatus.VERIFIED_SUCCESS,
            reason="INDEPENDENT_GITHUB_COMMIT_AND_FILE_INTEGRITY_VERIFIED",
            task_id=TASK_ID,
        )
        with patch(
            "jas_si_agent.agent_task_evidence_recollection.verify_github_repository_task",
            return_value=decision,
        ) as verify:
            store.finalize_success.return_value = True
            result = AgentTaskEvidenceRecollector(
                store=store, collector=collector, batch_size=3,
            ).run_once()

        verify.assert_called_once()
        store.finalize_success.assert_called_once_with(
            request_id=REQUEST_ID, task=claimed_request()[1], decision=decision,
        )
        store.record_inconclusive.assert_not_called()
        self.assertEqual(result.scanned, 1)
        self.assertEqual(result.finalized, 1)
        self.assertEqual(result.inconclusive, 0)
        self.assertEqual(result.lost_claim, 0)

    def test_inconclusive_evidence_never_calls_success_finalizer(self):
        store, collector = Mock(), Mock()
        store.claim_pending.return_value = [claimed_request()]
        decision = TaskVerificationDecision(
            status=VerificationStatus.INCONCLUSIVE,
            reason="INDEPENDENT_EVIDENCE_COLLECTION_FAILED",
            task_id=TASK_ID,
        )
        store.record_inconclusive.return_value = "pending"
        with patch(
            "jas_si_agent.agent_task_evidence_recollection.verify_github_repository_task",
            return_value=decision,
        ):
            result = AgentTaskEvidenceRecollector(
                store=store, collector=collector,
            ).run_once()

        store.record_inconclusive.assert_called_once_with(
            request_id=REQUEST_ID, task=claimed_request()[1],
            reason_code="INDEPENDENT_EVIDENCE_COLLECTION_FAILED",
        )
        store.finalize_success.assert_not_called()
        self.assertEqual(result.inconclusive, 1)
        self.assertEqual(result.finalized, 0)

    def test_lost_claim_is_not_reported_as_success_or_inconclusive(self):
        store, collector = Mock(), Mock()
        store.claim_pending.return_value = [claimed_request()]
        decision = TaskVerificationDecision(
            status=VerificationStatus.INCONCLUSIVE,
            reason="INDEPENDENT_EVIDENCE_COLLECTION_FAILED",
            task_id=TASK_ID,
        )
        store.record_inconclusive.return_value = None
        with patch(
            "jas_si_agent.agent_task_evidence_recollection.verify_github_repository_task",
            return_value=decision,
        ):
            result = AgentTaskEvidenceRecollector(store=store, collector=collector).run_once()
        self.assertEqual(result.lost_claim, 1)
        store.finalize_success.assert_not_called()

    def test_batch_size_is_bounded(self):
        for size in (0, 21, True, 1.5):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    AgentTaskEvidenceRecollector(
                        store=Mock(), collector=Mock(), batch_size=size,
                    )


if __name__ == "__main__":
    unittest.main()
