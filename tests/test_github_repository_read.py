from __future__ import annotations

import threading
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from jas_si_agent.agent_task_worker_store import AgentTaskLease
from jas_si_agent.github_installations import TenantGitHubInstallationCredential
from jas_si_agent.github_repository_read import build_github_repository_read_handler


TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000011")
OTHER_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000012")
TASK_ID = uuid.UUID("00000000-0000-0000-0000-000000000013")
COMMIT_SHA = "a" * 40


def make_lease(*, tenant_id=TENANT_ID, input_payload=None):
    return AgentTaskLease(
        task_id=TASK_ID,
        tenant_id=tenant_id,
        task_type="github.read_repository",
        input_payload=input_payload or {
            "repository": "owner/project",
            "commit_sha": COMMIT_SHA,
            "paths": ["README.md"],
        },
        attempt_count=1,
        max_attempts=3,
        lease_fence=1,
        lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
    )


class FakeCredentialProvider:
    def __init__(self, credential=None, error=None):
        self.credential = credential
        self.error = error
        self.calls = []

    def resolve(self, *, tenant_id, repository):
        self.calls.append((tenant_id, repository))
        if self.error:
            raise self.error
        return self.credential


class GitHubRepositoryReadHandlerTests(unittest.TestCase):
    def test_public_repository_read_uses_no_global_credential(self):
        provider = FakeCredentialProvider()
        handler = build_github_repository_read_handler(provider)
        lease = make_lease()
        with patch(
            "jas_si_agent.github_repository_read._verify_github_evidence",
            return_value={"status": "EVIDENCE_INTEGRITY_VERIFIED", "semantic_truth_verified": False},
        ) as verify:
            result = handler.execute(lease, threading.Event())

        self.assertEqual(provider.calls, [(TENANT_ID, "owner/project")])
        self.assertIsNone(verify.call_args.kwargs["access_token"])
        self.assertEqual(verify.call_args.kwargs["access_mode"], "public_repository_only")
        self.assertFalse(result["semantic_truth_verified"])

    def test_private_repository_uses_only_matching_tenant_installation(self):
        credential = TenantGitHubInstallationCredential(
            tenant_id=TENANT_ID,
            installation_id=123,
            repository="owner/project",
            access_token="installation-token",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        provider = FakeCredentialProvider(credential)
        handler = build_github_repository_read_handler(provider)
        with patch(
            "jas_si_agent.github_repository_read._verify_github_evidence",
            return_value={"status": "EVIDENCE_INTEGRITY_VERIFIED", "semantic_truth_verified": False},
        ) as verify:
            result = handler.execute(make_lease(), threading.Event())

        self.assertEqual(verify.call_args.kwargs["access_token"], "installation-token")
        self.assertEqual(
            verify.call_args.kwargs["access_mode"],
            "tenant_github_app_installation",
        )
        self.assertNotIn("installation-token", str(result))

    def test_tenant_mismatch_fails_closed_before_github_request(self):
        credential = TenantGitHubInstallationCredential(
            tenant_id=OTHER_TENANT_ID,
            installation_id=123,
            repository="owner/project",
            access_token="installation-token",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        handler = build_github_repository_read_handler(FakeCredentialProvider(credential))
        with patch("jas_si_agent.github_repository_read._verify_github_evidence") as verify:
            with self.assertRaisesRegex(RuntimeError, "tenant binding mismatch"):
                handler.execute(make_lease(), threading.Event())
        verify.assert_not_called()

    def test_invalid_task_input_fails_before_provider_or_github_request(self):
        provider = FakeCredentialProvider()
        handler = build_github_repository_read_handler(provider)
        lease = make_lease(input_payload={
            "repository": "owner/project",
            "commit_sha": "mutable-branch",
            "paths": ["../secret"],
        })
        with patch("jas_si_agent.github_repository_read._verify_github_evidence") as verify:
            with self.assertRaisesRegex(ValueError, "input is invalid"):
                handler.execute(lease, threading.Event())
        self.assertEqual(provider.calls, [])
        verify.assert_not_called()

    def test_cancelled_task_does_not_resolve_credentials_or_call_github(self):
        provider = FakeCredentialProvider()
        handler = build_github_repository_read_handler(provider)
        cancelled = threading.Event()
        cancelled.set()
        with patch("jas_si_agent.github_repository_read._verify_github_evidence") as verify:
            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                handler.execute(make_lease(), cancelled)
        self.assertEqual(provider.calls, [])
        verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
