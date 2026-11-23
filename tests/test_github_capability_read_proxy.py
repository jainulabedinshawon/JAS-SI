"""Security tests for Broker-owned GitHub content reads."""
from __future__ import annotations

import base64
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

from jas_si_agent.github_capability_broker import (
    GitHubCapabilityBrokerError,
    ResolvedGitHubTaskCapability,
)
from jas_si_agent.github_capability_read_proxy import GitHubCapabilityReadProxy


class GitHubCapabilityReadProxyTests(unittest.TestCase):
    def setUp(self):
        self.capability = ResolvedGitHubTaskCapability(
            task_id=uuid4(),
            tenant_id=uuid4(),
            installation_id=12345,
            repository_full_name="owner/private-repo",
            capability_role="worker",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            commit_sha="a" * 40,
            repository_paths=["src/allowed.py"],
        )
        self.issuer = Mock()
        self.issuer.issue.return_value = SimpleNamespace(
            installation_id=12345,
            repository="owner/private-repo",
            access_token="ghs-test-secret",
        )
        self.http = Mock()
        self.http.get.return_value.status_code = 200
        self.http.get.return_value.json.return_value = {
            "type": "file",
            "path": "src/allowed.py",
            "encoding": "base64",
            "content": base64.b64encode(b"print('ok')").decode("ascii"),
            "sha": "b" * 40,
        }
        self.proxy = GitHubCapabilityReadProxy(self.issuer, http_client=self.http)

    def test_reads_only_exact_capability_and_returns_no_token(self):
        result = self.proxy.read_file(
            capability=self.capability,
            repository="owner/private-repo",
            commit_sha="a" * 40,
            path="src/allowed.py",
        )
        self.issuer.issue.assert_called_once_with(
            installation_id=12345, repository="owner/private-repo"
        )
        self.assertEqual(self.http.get.call_args.kwargs["params"], {"ref": "a" * 40})
        self.assertEqual(base64.b64decode(result["content_base64"]), b"print('ok')")
        self.assertNotIn("access_token", result)
        self.assertNotIn("ghs-test-secret", repr(result))

    def test_rejects_unlisted_path_before_token_issuance(self):
        with self.assertRaises(GitHubCapabilityBrokerError):
            self.proxy.read_file(
                capability=self.capability,
                repository="owner/private-repo",
                commit_sha="a" * 40,
                path="src/private.py",
            )
        self.issuer.issue.assert_not_called()
        self.http.get.assert_not_called()

    def test_rejects_token_repository_scope_mismatch(self):
        self.issuer.issue.return_value = SimpleNamespace(
            installation_id=12345,
            repository="other/repo",
            access_token="ghs-test-secret",
        )
        with self.assertRaises(GitHubCapabilityBrokerError):
            self.proxy.read_file(
                capability=self.capability,
                repository="owner/private-repo",
                commit_sha="a" * 40,
                path="src/allowed.py",
            )
        self.http.get.assert_not_called()

    def test_rejects_non_file_and_invalid_content_response(self):
        self.http.get.return_value.json.return_value["type"] = "dir"
        with self.assertRaises(GitHubCapabilityBrokerError):
            self.proxy.read_file(
                capability=self.capability,
                repository="owner/private-repo",
                commit_sha="a" * 40,
                path="src/allowed.py",
            )

    def test_rejects_oversized_content(self):
        self.proxy = GitHubCapabilityReadProxy(
            self.issuer, http_client=self.http, max_content_bytes=4
        )
        with self.assertRaises(GitHubCapabilityBrokerError):
            self.proxy.read_file(
                capability=self.capability,
                repository="owner/private-repo",
                commit_sha="a" * 40,
                path="src/allowed.py",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
