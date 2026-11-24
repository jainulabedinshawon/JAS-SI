from __future__ import annotations

import os
import unittest
import uuid
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from jas_si_agent.github_task_verifier import (
    CollectedGitHubEvidence,
    TenantGitHubEvidenceCollector,
    PersistedTask,
    WorkerTaskReport,
    verify_github_repository_task,
)
from jas_si_agent.verification import VerificationStatus
from jas_si_agent.verify_router import _github_headers


TENANT = uuid.UUID("00000000-0000-0000-0000-000000000021")
TASK = uuid.UUID("00000000-0000-0000-0000-000000000022")
SHA = "a" * 40


def make_task():
    return PersistedTask(
        task_id=TASK,
        tenant_id=TENANT,
        task_type="github.read_repository",
        input_payload={
            "repository": "owner/project",
            "commit_sha": SHA,
            "paths": ["README.md"],
        },
    )


def make_report(**updates):
    result = {
        "task_type": "github.read_repository",
        "repository": "owner/project",
        "commit_sha": SHA,
        # Worker evidence is untrusted until compared with a fresh collector read.
        "semantic_truth_verified": False,
        "evidence_integrity": {
            "status": "EVIDENCE_INTEGRITY_VERIFIED",
            "verification_scope": "github_commit_and_file_integrity",
            "repository": "owner/project",
            "commit_sha": SHA,
            "tree_sha": "b" * 40,
            "files_verified": 1,
            "read_only": True,
            "semantic_truth_verified": False,
            "files": [{
                "path": "README.md",
                "blob_sha": "c" * 40,
                "sha256": "d" * 64,
                "size_bytes": 123,
                "integrity": "VERIFIED",
            }],
        },
    }
    result.update(updates)
    return WorkerTaskReport(TASK, True, result)


def make_evidence():
    return CollectedGitHubEvidence(
        collector_id="github-api-collector-v1",
        collected_at=datetime.now(timezone.utc),
        repository="owner/project",
        commit_sha=SHA,
        tree_sha="b" * 40,
        files=({
            "path": "README.md",
            "blob_sha": "c" * 40,
            "sha256": "d" * 64,
            "size_bytes": 123,
            "integrity": "VERIFIED",
        },),
        content_digest="62e0b41e95d976ac90506102aa1fba35b1d520113c5e5aee1e9787a81fc12af9",
    )


class GitHubTaskVerifierTests(unittest.TestCase):
    def test_success_requires_fresh_independent_collection(self):
        collector = Mock()
        collector.collect.return_value = make_evidence()

        result = verify_github_repository_task(
            make_task(),
            make_report(),
            collector=collector,
        )

        collector.collect.assert_called_once_with(
            tenant_id=TENANT,
            repository="owner/project",
            commit_sha=SHA,
            paths=("README.md",),
        )
        self.assertEqual(result.status, VerificationStatus.VERIFIED_SUCCESS)
        self.assertEqual(
            result.reason,
            "INDEPENDENT_GITHUB_COMMIT_AND_FILE_INTEGRITY_VERIFIED",
        )

    def test_worker_forged_evidence_does_not_replace_collector(self):
        collector = Mock()
        collector.collect.side_effect = RuntimeError("collector offline")
        report = make_report(
            evidence_integrity={"status": "EVIDENCE_INTEGRITY_VERIFIED"},
            semantic_truth_verified=True,
        )

        result = verify_github_repository_task(
            make_task(),
            report,
            collector=collector,
        )

        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "INDEPENDENT_EVIDENCE_COLLECTION_FAILED")
        collector.collect.assert_called_once()

    def test_task_report_binding_mismatch_is_inconclusive(self):
        collector = Mock()
        report = WorkerTaskReport(uuid.uuid4(), True, make_report().result_payload)

        result = verify_github_repository_task(
            make_task(),
            report,
            collector=collector,
        )

        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "TASK_REPORT_ID_MISMATCH")
        collector.collect.assert_not_called()

    def test_worker_report_must_match_immutable_task_request(self):
        collector = Mock()
        report = make_report(repository="attacker/other")

        result = verify_github_repository_task(
            make_task(),
            report,
            collector=collector,
        )

        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "WORKER_REPORT_REQUEST_MISMATCH")
        collector.collect.assert_not_called()

    def test_worker_report_hash_mismatch_is_inconclusive(self):
        collector = Mock()
        collector.collect.return_value = make_evidence()
        report = make_report()
        payload = dict(report.result_payload)
        worker_evidence = dict(payload["evidence_integrity"])
        worker_evidence["files"] = [{
            "path": "README.md",
            "blob_sha": "f" * 40,
            "sha256": "d" * 64,
            "size_bytes": 123,
            "integrity": "VERIFIED",
        }]
        payload["evidence_integrity"] = worker_evidence
        forged_report = WorkerTaskReport(TASK, True, payload)

        result = verify_github_repository_task(
            make_task(),
            forged_report,
            collector=collector,
        )

        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "WORKER_EVIDENCE_FILE_MISMATCH")

    def test_wrong_collected_file_set_is_inconclusive(self):
        collector = Mock()
        evidence = make_evidence()
        collector.collect.return_value = CollectedGitHubEvidence(
            collector_id=evidence.collector_id,
            collected_at=evidence.collected_at,
            repository=evidence.repository,
            commit_sha=evidence.commit_sha,
            tree_sha=evidence.tree_sha,
            files=(),
            content_digest=evidence.content_digest,
        )

        result = verify_github_repository_task(
            make_task(),
            make_report(),
            collector=collector,
        )

        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(result.reason, "INDEPENDENT_EVIDENCE_FILE_SET_MISMATCH")

    def test_worker_reported_failure_is_not_inferred_without_failure_evidence(self):
        collector = Mock()
        report = WorkerTaskReport(TASK, False, make_report().result_payload)

        result = verify_github_repository_task(
            make_task(),
            report,
            collector=collector,
        )

        self.assertEqual(result.status, VerificationStatus.INCONCLUSIVE)
        self.assertEqual(
            result.reason,
            "WORKER_REPORTED_FAILURE_REQUIRES_SEPARATE_FAILURE_EVIDENCE",
        )
        collector.collect.assert_not_called()


    def test_public_only_headers_ignore_ambient_legacy_token(self):
        with patch.dict(os.environ, {"JAS_SI_GITHUB_TOKEN": "legacy-process-token"}):
            headers = _github_headers(
                access_token=None,
                allow_legacy_env_token=False,
            )
        self.assertNotIn("Authorization", headers)

    def test_tenant_collector_disables_process_wide_token_fallback(self):
        provider = Mock()
        provider.resolve.return_value = None
        result = {
            "repository": "owner/project",
            "commit_sha": SHA,
            "tree_sha": "b" * 40,
            "files": [{
                "path": "README.md",
                "blob_sha": "c" * 40,
                "sha256": "d" * 64,
                "size_bytes": 123,
                "integrity": "VERIFIED",
            }],
        }
        collector = TenantGitHubEvidenceCollector(
            collector_id="tenant-verifier-test",
            credential_provider=provider,
        )
        with patch(
            "jas_si_agent.github_task_verifier._verify_github_evidence",
            return_value=result,
        ) as verify:
            collector.collect(
                tenant_id=TENANT,
                repository="owner/project",
                commit_sha=SHA,
                paths=("README.md",),
            )
        self.assertIsNone(verify.call_args.kwargs["access_token"])
        self.assertFalse(verify.call_args.kwargs["allow_legacy_env_token"])

if __name__ == "__main__":
    unittest.main()
