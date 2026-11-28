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
from jas_si_agent.github_capability_read_proxy import (
    GitHubCapabilityReadProxy,
    _MAX_API_RESPONSE_BYTES,
)


class _StreamingResponse:
    def __init__(self, body, *, status_code=200, headers=None, chunk_size=65536):
        self.status_code = status_code
        self.headers = headers or {}
        self.body = body
        self.chunk_size = chunk_size
        self.iterated = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def iter_bytes(self, chunk_size=65536):
        self.iterated = True
        for offset in range(0, len(self.body), min(chunk_size, self.chunk_size)):
            yield self.body[offset:offset + min(chunk_size, self.chunk_size)]


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
        content = b"print('ok')"
        expected_blob_sha = hashlib.sha1(f"blob {len(content)}\\0".encode("ascii") + content).hexdigest()
        self.payload = {
            "type": "file",
            "path": "src/allowed.py",
            "encoding": "base64",
            "content": base64.b64encode(content).decode("ascii"),
            "sha": expected_blob_sha,
        }
        self.response = _StreamingResponse(
            __import__("json").dumps(self.payload).encode("utf-8")
        )
        self.http.stream.return_value = self.response
        self.proxy = GitHubCapabilityReadProxy(self.issuer, http_client=self.http)

    def test_close_releases_broker_http_client(self):
        self.proxy.close()
        self.http.close.assert_called_once_with()

    def test_reads_immutable_commit_tree_metadata_without_token(self):
        payload = {
            "sha": "a" * 40,
            "commit": {"tree": {"sha": "c" * 40}},
        }
        response = _StreamingResponse(__import__("json").dumps(payload).encode("utf-8"))
        self.http.stream.return_value = response
        result = self.proxy.read_commit(
            capability=self.capability,
            repository="owner/private-repo",
            commit_sha="a" * 40,
        )
        self.assertEqual(result, {
            "repository": "owner/private-repo",
            "commit_sha": "a" * 40,
            "tree_sha": "c" * 40,
        })
        self.assertNotIn("access_token", repr(result))
        self.assertNotIn("ghs-test-secret", repr(result))

    def test_rejects_commit_metadata_scope_mismatch_before_token_issuance(self):
        with self.assertRaises(GitHubCapabilityBrokerError):
            self.proxy.read_commit(
                capability=self.capability,
                repository="owner/other-repo",
                commit_sha="a" * 40,
            )
        self.issuer.issue.assert_not_called()
        self.http.stream.assert_not_called()

    def test_rejects_commit_response_for_different_sha_or_invalid_tree(self):
        for payload in (
            {"sha": "d" * 40, "commit": {"tree": {"sha": "c" * 40}}},
            {"sha": "a" * 40, "commit": {"tree": {"sha": "invalid"}}},
        ):
            with self.subTest(payload=payload):
                self.http.stream.return_value = _StreamingResponse(
                    __import__("json").dumps(payload).encode("utf-8")
                )
                with self.assertRaises(GitHubCapabilityBrokerError):
                    self.proxy.read_commit(
                        capability=self.capability,
                        repository="owner/private-repo",
                        commit_sha="a" * 40,
                    )

    def test_rejects_oversized_commit_metadata_response(self):
        response = _StreamingResponse(
            b'{"padding":"' + (b"x" * (_MAX_API_RESPONSE_BYTES + 1)) + b'"}',
            chunk_size=4096,
        )
        self.http.stream.return_value = response
        with self.assertRaises(GitHubCapabilityBrokerError):
            self.proxy.read_commit(
                capability=self.capability,
                repository="owner/private-repo",
                commit_sha="a" * 40,
            )
        self.assertTrue(response.iterated)

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
        self.assertEqual(self.http.stream.call_args.kwargs["params"], {"ref": "a" * 40})
        self.assertEqual(base64.b64decode(result["content_base64"]), b"print('ok')")
        self.assertNotIn("access_token", result)
        self.assertNotIn("ghs-test-secret", repr(result))

    def test_rejects_content_whose_git_blob_hash_does_not_match(self):
        self.payload["sha"] = "b" * 40
        self.http.stream.return_value = _StreamingResponse(
            json.dumps(self.payload).encode("utf-8")
        )
        with self.assertRaisesRegex(GitHubCapabilityBrokerError, "blob integrity"):
            self.proxy.read_file(
                capability=self.capability,
                repository="owner/private-repo",
                commit_sha="a" * 40,
                path="src/allowed.py",
            )

    def test_rejects_unlisted_path_before_token_issuance(self):
        with self.assertRaises(GitHubCapabilityBrokerError):
            self.proxy.read_file(
                capability=self.capability,
                repository="owner/private-repo",
                commit_sha="a" * 40,
                path="src/private.py",
            )
        self.issuer.issue.assert_not_called()
        self.http.stream.assert_not_called()

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
        self.http.stream.assert_not_called()

    def test_rejects_non_file_and_invalid_content_response(self):
        self.payload["type"] = "dir"
        self.http.stream.return_value = _StreamingResponse(
            __import__("json").dumps(self.payload).encode("utf-8")
        )
        with self.assertRaises(GitHubCapabilityBrokerError):
            self.proxy.read_file(
                capability=self.capability,
                repository="owner/private-repo",
                commit_sha="a" * 40,
                path="src/allowed.py",
            )

    def test_rejects_oversized_decoded_file(self):
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

    def test_rejects_oversized_api_body_during_stream_before_json_parse(self):
        response = _StreamingResponse(
            b'{"padding":"' + (b"x" * (_MAX_API_RESPONSE_BYTES + 1)) + b'"}',
            chunk_size=4096,
        )
        self.http.stream.return_value = response
        with self.assertRaises(GitHubCapabilityBrokerError):
            self.proxy.read_file(
                capability=self.capability,
                repository="owner/private-repo",
                commit_sha="a" * 40,
                path="src/allowed.py",
            )
        self.assertTrue(response.iterated)

    def test_rejects_declared_oversized_api_body_before_streaming(self):
        response = _StreamingResponse(
            b"{}", headers={"content-length": str(_MAX_API_RESPONSE_BYTES + 1)}
        )
        self.http.stream.return_value = response
        with self.assertRaises(GitHubCapabilityBrokerError):
            self.proxy.read_file(
                capability=self.capability,
                repository="owner/private-repo",
                commit_sha="a" * 40,
                path="src/allowed.py",
            )
        self.assertFalse(response.iterated)


if __name__ == "__main__":
    unittest.main(verbosity=2)
