from __future__ import annotations

import base64
import hashlib
import unittest
from unittest.mock import MagicMock, Mock
from uuid import uuid4

from jas_si_agent.github_capability_client import (
    GitHubCapabilityBrokerClient,
    GitHubCapabilityClientError,
)


class GitHubCapabilityBrokerClientTests(unittest.TestCase):
    def setUp(self):
        self.http = Mock()
        self.client = GitHubCapabilityBrokerClient(
            base_url="https://broker.internal",
            client_certificate_path="/unused/cert.pem",
            client_key_path="/unused/key.pem",
            ca_bundle_path="/unused/ca.pem",
            http_client=self.http,
        )
        self.task_id = uuid4()
        self.commit_sha = "a" * 40

    def _response(self, payload, status=200):
        import json
        response = MagicMock()
        response.status_code = status
        response.headers = {"content-length": str(len(json.dumps(payload).encode()))}
        response.content = json.dumps(payload).encode()
        response.iter_bytes.return_value = [response.content]
        response.__enter__.return_value = response
        return response

    def test_worker_read_uses_persisted_lease_fence_and_recomputes_git_blob(self):
        content = b"verified source\n"
        blob_sha = hashlib.sha1(
            b"blob " + str(len(content)).encode() + b"\0" + content
        ).hexdigest()
        self.http.stream.return_value = self._response({
            "repository": "owner/private",
            "commit_sha": self.commit_sha,
            "path": "src/app.py",
            "blob_sha": blob_sha,
            "content_base64": base64.b64encode(content).decode(),
            "content_bytes": len(content),
        })
        result = self.client.read_file(
            task_id=self.task_id, repository="owner/private",
            commit_sha=self.commit_sha, path="src/app.py",
            role="worker", lease_fence=17,
        )
        self.assertEqual(result["content"], content)
        self.assertEqual(result["blob_sha"], blob_sha)
        payload = self.http.post.call_args.kwargs["json"]
        self.assertEqual(payload["lease_fence"], 17)
        self.assertNotIn("verifier_claim_token", payload)

    def test_verifier_read_uses_claim_token_not_worker_fence(self):
        claim = uuid4()
        self.http.post.return_value = self._response({
            "repository": "owner/private", "commit_sha": self.commit_sha,
            "tree_sha": "b" * 40,
        })
        result = self.client.read_commit(
            task_id=self.task_id, repository="owner/private",
            commit_sha=self.commit_sha, role="verifier",
            verifier_claim_token=claim,
        )
        self.assertEqual(result["tree_sha"], "b" * 40)
        payload = self.http.post.call_args.kwargs["json"]
        self.assertEqual(payload["verifier_claim_token"], str(claim))
        self.assertNotIn("lease_fence", payload)

    def test_rejects_missing_or_cross_role_proof_before_network(self):
        with self.assertRaises(ValueError):
            self.client.read_commit(
                task_id=self.task_id, repository="owner/private",
                commit_sha=self.commit_sha, role="worker",
            )
        with self.assertRaises(ValueError):
            self.client.read_commit(
                task_id=self.task_id, repository="owner/private",
                commit_sha=self.commit_sha, role="verifier",
                verifier_claim_token=uuid4(), lease_fence=4,
            )
        self.http.stream.assert_not_called()

    def test_rejects_tampered_blob_content(self):
        content = b"actual bytes"
        self.http.post.return_value = self._response({
            "repository": "owner/private", "commit_sha": self.commit_sha,
            "path": "src/app.py", "blob_sha": "c" * 40,
            "content_base64": base64.b64encode(content).decode(),
            "content_bytes": len(content),
        })
        with self.assertRaises(GitHubCapabilityClientError):
            self.client.read_file(
                task_id=self.task_id, repository="owner/private",
                commit_sha=self.commit_sha, path="src/app.py",
                role="worker", lease_fence=2,
            )

    def test_rejects_path_traversal_and_repository_commit_substitution(self):
        with self.assertRaises(ValueError):
            self.client.read_file(
                task_id=self.task_id, repository="owner/private",
                commit_sha=self.commit_sha, path="../secrets",
                role="worker", lease_fence=2,
            )
        self.http.post.return_value = self._response({
            "repository": "owner/other", "commit_sha": self.commit_sha,
            "tree_sha": "b" * 40,
        })
        with self.assertRaises(GitHubCapabilityClientError):
            self.client.read_commit(
                task_id=self.task_id, repository="owner/private",
                commit_sha=self.commit_sha, role="worker", lease_fence=2,
            )

    def test_rejects_oversized_streamed_broker_response(self):
        response = MagicMock()
        response.status_code = 200
        response.headers = {}
        response.iter_bytes.return_value = [b"x" * (2 * 1024 * 1024 + 1)]
        response.__enter__.return_value = response
        self.http.stream.return_value = response
        with self.assertRaises(GitHubCapabilityClientError):
            self.client.read_commit(
                task_id=self.task_id, repository="owner/private",
                commit_sha=self.commit_sha, role="worker", lease_fence=3,
            )

    def test_requires_https_origin(self):
        with self.assertRaises(ValueError):
            GitHubCapabilityBrokerClient(
                base_url="http://broker.internal",
                client_certificate_path="cert", client_key_path="key",
                ca_bundle_path="ca", http_client=self.http,
            )


if __name__ == "__main__":
    unittest.main()
