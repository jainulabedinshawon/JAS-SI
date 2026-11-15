from __future__ import annotations

import unittest
import uuid
from datetime import datetime, timedelta, timezone

from jas_si_agent.github_installations import (
    GitHubCredentialResolutionError,
    TenantGitHubInstallationCredential,
    resolve_tenant_github_credential,
)


class FakeProvider:
    def __init__(self, credential=None, error=None):
        self.credential = credential
        self.error = error
        self.calls = []

    def resolve(self, *, tenant_id, repository):
        self.calls.append((tenant_id, repository))
        if self.error:
            raise self.error
        return self.credential


class TenantGitHubInstallationTests(unittest.TestCase):
    def setUp(self):
        self.tenant_id = uuid.uuid4()
        self.other_tenant_id = uuid.uuid4()
        self.now = datetime.now(timezone.utc)
        self.credential = TenantGitHubInstallationCredential(
            tenant_id=self.tenant_id,
            installation_id=12345,
            repository="Example/Private-Repo",
            access_token="installation-token-secret",
            expires_at=self.now + timedelta(minutes=30),
        )

    def test_matching_tenant_and_repository_resolves(self):
        provider = FakeProvider(self.credential)
        result = resolve_tenant_github_credential(
            provider,
            tenant_id=self.tenant_id,
            repository="example/private-repo",
            now=self.now,
        )
        self.assertEqual(result, self.credential)
        self.assertEqual(
            provider.calls, [(self.tenant_id, "example/private-repo")]
        )

    def test_cross_tenant_credential_is_rejected(self):
        with self.assertRaises(GitHubCredentialResolutionError):
            resolve_tenant_github_credential(
                FakeProvider(self.credential),
                tenant_id=self.other_tenant_id,
                repository="Example/Private-Repo",
                now=self.now,
            )

    def test_cross_repository_credential_is_rejected(self):
        with self.assertRaises(GitHubCredentialResolutionError):
            resolve_tenant_github_credential(
                FakeProvider(self.credential),
                tenant_id=self.tenant_id,
                repository="Example/Other-Repo",
                now=self.now,
            )

    def test_expired_credential_is_rejected(self):
        expired = TenantGitHubInstallationCredential(
            tenant_id=self.tenant_id,
            installation_id=12345,
            repository="Example/Private-Repo",
            access_token="expired-token",
            expires_at=self.now - timedelta(seconds=1),
        )
        with self.assertRaises(GitHubCredentialResolutionError):
            resolve_tenant_github_credential(
                FakeProvider(expired),
                tenant_id=self.tenant_id,
                repository="Example/Private-Repo",
                now=self.now,
            )

    def test_missing_installation_returns_none(self):
        self.assertIsNone(
            resolve_tenant_github_credential(
                FakeProvider(None),
                tenant_id=self.tenant_id,
                repository="Example/Private-Repo",
                now=self.now,
            )
        )

    def test_provider_failure_is_redacted(self):
        with self.assertRaisesRegex(
            GitHubCredentialResolutionError, "unavailable"
        ) as raised:
            resolve_tenant_github_credential(
                FakeProvider(error=RuntimeError("private token leaked")),
                tenant_id=self.tenant_id,
                repository="Example/Private-Repo",
                now=self.now,
            )
        self.assertNotIn("private token leaked", str(raised.exception))

    def test_token_is_not_exposed_by_repr_or_equality(self):
        other = TenantGitHubInstallationCredential(
            tenant_id=self.tenant_id,
            installation_id=12345,
            repository="Example/Private-Repo",
            access_token="different-secret",
            expires_at=self.credential.expires_at,
        )
        self.assertNotIn(self.credential.access_token, repr(self.credential))
        self.assertEqual(self.credential, other)

    def test_invalid_installation_and_token_fields_are_rejected(self):
        for installation_id, token in ((0, "token"), (True, "token"), (1, "")):
            with self.subTest(installation_id=installation_id, token=token):
                with self.assertRaises(ValueError):
                    TenantGitHubInstallationCredential(
                        tenant_id=self.tenant_id,
                        installation_id=installation_id,
                        repository="Example/Private-Repo",
                        access_token=token,
                        expires_at=self.now + timedelta(minutes=5),
                    )

    def test_naive_expiry_is_rejected(self):
        with self.assertRaises(ValueError):
            TenantGitHubInstallationCredential(
                tenant_id=self.tenant_id,
                installation_id=12345,
                repository="Example/Private-Repo",
                access_token="token",
                expires_at=datetime.now(),
            )

    def test_naive_validation_clock_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve_tenant_github_credential(
                FakeProvider(self.credential),
                tenant_id=self.tenant_id,
                repository="Example/Private-Repo",
                now=datetime.now(),
            )


if __name__ == "__main__":
    unittest.main()
