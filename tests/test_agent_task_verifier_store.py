from __future__ import annotations

import hashlib
import sys
import types
import unittest
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

from jas_si_agent.agent_task_verifier_store import (
    PostgresAgentTaskVerifierStore,
)
from jas_si_agent.github_task_verifier import (
    CollectedGitHubEvidence,
    PersistedTask,
    TaskVerificationDecision,
)
from jas_si_agent.verification import VerificationStatus


TENANT = uuid.UUID("00000000-0000-0000-0000-000000000041")
TASK = uuid.UUID("00000000-0000-0000-0000-000000000042")
SHA = "a" * 40


def make_task():
    return PersistedTask(
        task_id=TASK,
        tenant_id=TENANT,
        task_type="github.read_repository",
        verifier_claim_token=uuid.UUID("00000000-0000-0000-0000-000000000043"),
        input_payload={
            "repository": "owner/project",
            "commit_sha": SHA,
            "paths": ["README.md"],
        },
    )


def make_evidence():
    files = ({
        "path": "README.md",
        "blob_sha": "c" * 40,
        "sha256": "d" * 64,
        "size_bytes": 123,
        "integrity": "VERIFIED",
    },)
    canonical = "|".join([
        "owner/project",
        SHA,
        "b" * 40,
        *[
            f"{item['path']}:{item['blob_sha']}:{item['sha256']}"
            for item in files
        ],
    ]).encode("utf-8")
    return CollectedGitHubEvidence(
        collector_id="trusted-github-collector-v1",
        collected_at=datetime.now(timezone.utc),
        repository="owner/project",
        commit_sha=SHA,
        tree_sha="b" * 40,
        files=files,
        content_digest=hashlib.sha256(canonical).hexdigest(),
    )


def make_decision(evidence=None, status=VerificationStatus.VERIFIED_SUCCESS):
    return TaskVerificationDecision(
        status=status,
        reason="INDEPENDENT_GITHUB_COMMIT_AND_FILE_INTEGRITY_VERIFIED",
        task_id=TASK,
        evidence=evidence if evidence is not None else make_evidence(),
    )


class FakeCursor:
    def __init__(self, row):
        self.row = row
        self.executed = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, query, params):
        self.executed = (query, params)

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.row


class FakeConnection:
    def __init__(self, row, capture):
        self.cursor_instance = FakeCursor(row)
        self.capture = capture

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.capture.append(self.cursor_instance.executed)
        return False

    def cursor(self):
        return self.cursor_instance


class AgentTaskVerifierStoreTests(unittest.TestCase):
    def make_store(self):
        return PostgresAgentTaskVerifierStore(
            "postgresql://dedicated-verifier"
        )

    def install_fake_psycopg(self, row, capture):
        def connect(dsn):
            self.assertEqual(dsn, "postgresql://dedicated-verifier")
            return FakeConnection(row, capture)

        psycopg = types.ModuleType("psycopg")
        psycopg.connect = connect
        psycopg_types = types.ModuleType("psycopg.types")
        psycopg_json = types.ModuleType("psycopg.types.json")

        class Jsonb:
            def __init__(self, obj):
                self.obj = obj

        psycopg_json.Jsonb = Jsonb
        modules = {
            "psycopg": psycopg,
            "psycopg.types": psycopg_types,
            "psycopg.types.json": psycopg_json,
        }
        return patch.dict(sys.modules, modules), Jsonb

    def test_claims_persisted_awaiting_verification_tasks(self):
        task_id = uuid.uuid4()
        tenant_id = uuid.uuid4()
        reported_at = datetime.now(timezone.utc)
        row = (
            task_id,
            tenant_id,
            "github.read_repository",
            {"repository": "owner/project", "commit_sha": SHA, "paths": ["README.md"]},
            {
                "task_type": "github.read_repository",
                "repository": "owner/project",
                "commit_sha": SHA,
                "evidence_integrity": {"status": "EVIDENCE_INTEGRITY_VERIFIED"},
            },
            reported_at,
            uuid.uuid4(),
        )
        capture = []
        context, _ = self.install_fake_psycopg([row], capture)
        with context:
            items = self.make_store().claim_awaiting_verification(limit=5)

        self.assertEqual(len(items), 1)
        task, report = items[0]
        self.assertEqual(task.task_id, task_id)
        self.assertEqual(task.tenant_id, tenant_id)
        self.assertIsInstance(task.verifier_claim_token, uuid.UUID)
        self.assertTrue(report.claimed_success)
        self.assertEqual(report.task_id, task_id)
        self.assertEqual(report.result_payload["repository"], "owner/project")
        self.assertIn("jas_si_agent_task_verification_claim", capture[0][0])
        self.assertEqual(capture[0][1], (5, 120))

    def test_verification_list_rejects_invalid_limit_before_database(self):
        for limit in (0, 21, True, 1.5):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    self.make_store().claim_awaiting_verification(limit=limit)

    def test_persists_inconclusive_outcome_with_claim_fence(self):
        capture = []
        context, _ = self.install_fake_psycopg(("awaiting_verification",), capture)
        task = make_task()
        with context:
            result = self.make_store().record_inconclusive(
                task=task,
                reason_code="INDEPENDENT_EVIDENCE_COLLECTION_FAILED",
            )

        self.assertEqual(result, "awaiting_verification")
        query, params = capture[0]
        self.assertIn("jas_si_agent_task_verification_record_inconclusive", query)
        self.assertEqual(params, (
            TASK,
            TENANT,
            task.verifier_claim_token,
            "INDEPENDENT_EVIDENCE_COLLECTION_FAILED",
        ))

    def test_inconclusive_reason_code_rejects_untrusted_text(self):
        with self.assertRaisesRegex(ValueError, "sanitized verifier reason"):
            self.make_store().record_inconclusive(
                task=make_task(),
                reason_code="collector failed; token=secret",
            )

    def test_persists_independent_evidence_and_calls_atomic_finalizer(self):
        capture = []
        context, Jsonb = self.install_fake_psycopg((True,), capture)
        task = make_task()
        decision = make_decision()

        with context:
            result = self.make_store().finalize_success(
                task=task,
                decision=decision,
            )

        self.assertTrue(result)
        query, params = capture[0]
        self.assertIn("jas_si_agent_task_finalize_success", query)
        self.assertEqual(len(params), 8)
        self.assertEqual(params[1:5], (
            TASK,
            TENANT,
            task.verifier_claim_token,
            "trusted-github-collector-v1",
        ))
        self.assertEqual(len(params[5]), 32)
        self.assertIsInstance(params[6], Jsonb)
        self.assertEqual(params[6].obj["task_id"], str(TASK))
        self.assertEqual(params[6].obj["tenant_id"], str(TENANT))
        self.assertEqual(
            params[6].obj["evidence_digest"],
            decision.evidence.content_digest,
        )

    def test_inconclusive_decision_never_reaches_database(self):
        def forbidden_connect(_dsn):
            self.fail("database must not be called for an inconclusive decision")

        psycopg = types.ModuleType("psycopg")
        psycopg.connect = forbidden_connect
        with patch.dict(sys.modules, {"psycopg": psycopg}):
            with self.assertRaisesRegex(ValueError, "Only independently verified"):
                self.make_store().finalize_success(
                    task=make_task(),
                    decision=make_decision(status=VerificationStatus.INCONCLUSIVE),
                )

    def test_task_id_mismatch_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "task binding mismatch"):
            self.make_store().finalize_success(
                task=make_task(),
                decision=TaskVerificationDecision(
                    status=VerificationStatus.VERIFIED_SUCCESS,
                    reason="test",
                    task_id=uuid.uuid4(),
                    evidence=make_evidence(),
                ),
            )

    def test_evidence_digest_tampering_is_rejected(self):
        evidence = make_evidence()
        tampered = CollectedGitHubEvidence(
            collector_id=evidence.collector_id,
            collected_at=evidence.collected_at,
            repository=evidence.repository,
            commit_sha=evidence.commit_sha,
            tree_sha=evidence.tree_sha,
            files=evidence.files,
            content_digest="f" * 64,
        )
        with self.assertRaisesRegex(ValueError, "digest does not match"):
            self.make_store().finalize_success(
                task=make_task(),
                decision=make_decision(evidence=tampered),
            )

    def test_non_github_task_is_rejected(self):
        task = PersistedTask(
            task_id=TASK,
            tenant_id=TENANT,
            task_type="reasoning",
            input_payload={},
        )
        with self.assertRaisesRegex(ValueError, "Only a persisted GitHub"):
            self.make_store().finalize_success(
                task=task,
                decision=make_decision(),
            )

    def test_database_can_decline_stale_or_already_finalized_task(self):
        capture = []
        context, _ = self.install_fake_psycopg((False,), capture)
        with context:
            result = self.make_store().finalize_success(
                task=make_task(),
                decision=make_decision(),
            )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
