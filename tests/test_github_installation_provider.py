from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from jas_si_agent.github_installation_provider import (
    PostgresTenantGitHubInstallationProvider,
)
from jas_si_agent.github_installations import GitHubCredentialResolutionError


class FakeCursor:
    def __init__(self, row=None, error=None):
        self.row = row
        self.error = error
        self.executed = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, params):
        self.executed = (query, params)
        if self.error:
            raise self.error

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self):
        return self._cursor


class FakeIssuer:
    def __init__(self, token=None, error=None):
        self.token = token
        self.error = error
        self.calls = []

    def issue(self, *, installation_id, repository):
        self.calls.append((installation_id, repository))
        if self.error:
            raise self.error
        return self.token


class IssuedToken:
    def __init__(self, installation_id, repository, expires_at=None):
        self.installation_id = installation_id
        self.repository = repository
        self.access_token = "short-lived-test-token"
        self.expires_at = expires_at or (
            datetime.now(timezone.utc) + timedelta(minutes=30)
        )


class PostgresTenantGitHubInstallationProviderTests(unittest.TestCase):
    def setUp(self):
        self.tenant_id = uuid4()
        self.repository = "Example/Private-Repo"
        self.installation_id = 183349938
        self.row = (self.tenant_id, self.installation_id, self.repository)
        self.cursor = FakeCursor(self.row)
        self.issuer = FakeIssuer(
            IssuedToken(self.installation_id, self.repository)
        )
        self.connections = []

        def connect(dsn):
            self.connections.append(dsn)
            return FakeConnection(self.cursor)

        self.provider = PostgresTenantGitHubInstallationProvider(
            database_dsn="postgresql://worker-role@db.example/agent",
            token_issuer=self.issuer,
            connection_factory=connect,
        )

    def test_resolves_verified_binding_and_mints_scoped_token(self):
        result = self.provider.resolve(
            tenant_id=self.tenant_id, repository=self.repository
        )
        self.assertEqual(result.tenant_id, self.tenant_id)
        self.assertEqual(result.installation_id, self.installation_id)
        self.assertEqual(result.repository, self.repository)
        self.assertEqual(result.access_token, "short-lived-test-token")
        self.assertEqual(self.issuer.calls, [(self.installation_id, self.repository)])
        self.assertEqual(len(self.connections), 1)
        query, params = self.cursor.executed
        self.assertIn("jas_si_github_installation_binding_resolve", query)
        self.assertEqual(params, (self.tenant_id, self.repository))

    def test_missing_verified_binding_returns_none_without_issuing_token(self):
        self.cursor.row = None
        result = self.provider.resolve(
            tenant_id=self.tenant_id, repository=self.repository
        )
        self.assertIsNone(result)
        self.assertEqual(self.issuer.calls, [])

    def test_cross_tenant_database_result_is_rejected(self):
        self.cursor.row = (uuid4(), self.installation_id, self.repository)
        with self.assertRaises(GitHubCredentialResolutionError):
            self.provider.resolve(
                tenant_id=self.tenant_id, repository=self.repository
            )
        self.assertEqual(self.issuer.calls, [])

    def test_cross_repository_database_result_is_rejected(self):
        self.cursor.row = (self.tenant_id, self.installation_id, "Other/Repo")
        with self.assertRaises(GitHubCredentialResolutionError):
            self.provider.resolve(
                tenant_id=self.tenant_id, repository=self.repository
            )
        self.assertEqual(self.issuer.calls, [])

    def test_invalid_database_installation_id_is_rejected(self):
        self.cursor.row = (self.tenant_id, True, self.repository)
        with self.assertRaises(GitHubCredentialResolutionError):
            self.provider.resolve(
                tenant_id=self.tenant_id, repository=self.repository
            )
        self.assertEqual(self.issuer.calls, [])

    def test_database_failure_is_redacted(self):
        self.cursor.error = RuntimeError("postgres://secret-password")
        with self.assertRaisesRegex(
            GitHubCredentialResolutionError, "binding is unavailable"
        ) as raised:
            self.provider.resolve(
                tenant_id=self.tenant_id, repository=self.repository
            )
        self.assertNotIn("secret-password", str(raised.exception))

    def test_issuer_failure_is_redacted(self):
        self.issuer.error = RuntimeError("private-key-content")
        with self.assertRaisesRegex(
            GitHubCredentialResolutionError, "credential is unavailable"
        ) as raised:
            self.provider.resolve(
                tenant_id=self.tenant_id, repository=self.repository
            )
        self.assertNotIn("private-key-content", str(raised.exception))

    def test_wrong_issuer_installation_is_rejected(self):
        self.issuer.token = IssuedToken(
            self.installation_id + 1, self.repository
        )
        with self.assertRaises(GitHubCredentialResolutionError):
            self.provider.resolve(
                tenant_id=self.tenant_id, repository=self.repository
            )

    def test_wrong_issuer_repository_is_rejected(self):
        self.issuer.token = IssuedToken(self.installation_id, "Other/Repo")
        with self.assertRaises(GitHubCredentialResolutionError):
            self.provider.resolve(
                tenant_id=self.tenant_id, repository=self.repository
            )

    def test_invalid_request_is_rejected_before_database_access(self):
        with self.assertRaises(GitHubCredentialResolutionError):
            self.provider.resolve(
                tenant_id="not-a-tenant", repository=self.repository
            )
        with self.assertRaises(GitHubCredentialResolutionError):
            self.provider.resolve(
                tenant_id=self.tenant_id, repository="../private"
            )
        self.assertEqual(self.connections, [])

    def test_requires_dedicated_dsn_and_trusted_issuer(self):
        with self.assertRaises(ValueError):
            PostgresTenantGitHubInstallationProvider(
                database_dsn=" ",
                token_issuer=self.issuer,
            )
        with self.assertRaises(ValueError):
            PostgresTenantGitHubInstallationProvider(
                database_dsn="postgresql://worker-role@db.example/agent",
                token_issuer=object(),
            )


if __name__ == "__main__":
    unittest.main()
