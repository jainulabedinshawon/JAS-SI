from __future__ import annotations

import hashlib
import unittest
from datetime import datetime, timezone
from threading import Event
from uuid import uuid4

from jas_si_agent.agent_task_worker_store import AgentTaskLease
from jas_si_agent.github_capability_evidence import (
    BrokerGitHubEvidenceCollector,
    build_broker_github_repository_read_handler,
)
from jas_si_agent.github_task_verifier import PersistedTask


class FakeBrokerClient:
    def __init__(self):
        self.calls = []

    def read_commit(self, **kwargs):
        self.calls.append(("commit", kwargs))
        return {"repository": "owner/private", "commit_sha": "a" * 40, "tree_sha": "b" * 40}

    def read_file(self, **kwargs):
        self.calls.append(("file", kwargs))
        content = b"from broker\n"
        blob = hashlib.sha1(
            b"blob " + str(len(content)).encode("ascii") + b"\0" + content
        ).hexdigest()
        return {
            "repository": "owner/private",
            "commit_sha": "a" * 40,
            "path": kwargs["path"],
            "blob_sha": blob,
            "sha256": hashlib.sha256(content).hexdigest(),
            "content": content,
        }


class BrokerEvidenceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.task_id = uuid4()
        self.tenant_id = uuid4()
        self.claim_token = uuid4()
        self.client = FakeBrokerClient()
        self.lease = AgentTaskLease(
            task_id=self.task_id,
            tenant_id=self.tenant_id,
            task_type="github.read_repository",
            input_payload={
                "repository": "owner/private",
                "commit_sha": "a" * 40,
                "paths": ["src/app.py"],
            },
            attempt_count=1,
            max_attempts=3,
            lease_fence=9,
            lease_expires_at=datetime.now(timezone.utc),
        )

    def test_worker_handler_uses_lease_fence_and_never_receives_token(self):
        handler = build_broker_github_repository_read_handler(self.client)
        result = handler.execute(self.lease, Event())
        self.assertFalse(result["semantic_truth_verified"])
        self.assertEqual(result["evidence_integrity"]["tree_sha"], "b" * 40)
        self.assertEqual(result["evidence_integrity"]["files_verified"], 1)
        self.assertEqual(self.client.calls[0][1]["role"], "worker")
        self.assertEqual(self.client.calls[0][1]["lease_fence"], 9)
        self.assertNotIn("access_token", result)

    def test_verifier_collector_requires_persisted_claim_and_uses_fresh_reads(self):
        collector = BrokerGitHubEvidenceCollector(
            collector_id="staging-verifier",
            broker_client=self.client,
        )
        task = PersistedTask(
            task_id=self.task_id,
            tenant_id=self.tenant_id,
            task_type="github.read_repository",
            input_payload=self.lease.input_payload,
            verifier_claim_token=self.claim_token,
        )
        evidence = collector.collect_for_task(
            task=task,
            repository="owner/private",
            commit_sha="a" * 40,
            paths=("src/app.py",),
        )
        self.assertEqual(evidence.tree_sha, "b" * 40)
        self.assertEqual(evidence.files[0]["integrity"], "VERIFIED")
        self.assertEqual(self.client.calls[0][1]["role"], "verifier")
        self.assertEqual(self.client.calls[0][1]["verifier_claim_token"], self.claim_token)
        self.assertNotIn("lease_fence", self.client.calls[0][1])

    def test_verifier_collector_rejects_missing_persisted_claim(self):
        collector = BrokerGitHubEvidenceCollector(
            collector_id="staging-verifier",
            broker_client=self.client,
        )
        task = PersistedTask(
            task_id=self.task_id,
            tenant_id=self.tenant_id,
            task_type="github.read_repository",
            input_payload=self.lease.input_payload,
            verifier_claim_token=None,
        )
        with self.assertRaises(ValueError):
            collector.collect_for_task(
                task=task,
                repository="owner/private",
                commit_sha="a" * 40,
                paths=("src/app.py",),
            )
        self.assertEqual(self.client.calls, [])

    def test_legacy_collector_protocol_fails_closed(self):
        collector = BrokerGitHubEvidenceCollector(
            collector_id="staging-verifier",
            broker_client=self.client,
        )
        with self.assertRaises(RuntimeError):
            collector.collect(
                tenant_id=self.tenant_id,
                repository="owner/private",
                commit_sha="a" * 40,
                paths=("src/app.py",),
            )
        self.assertEqual(self.client.calls, [])


if __name__ == "__main__":
    unittest.main()
