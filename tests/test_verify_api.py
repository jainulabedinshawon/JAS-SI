from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest

from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import httpx

from fastapi.testclient import TestClient

from jas_si_agent import api
from jas_si_agent.security_event_store import JsonlSecurityEventStore
from jas_si_agent import verify_router

TEST_API_KEY = "test-only-jas-si-api-key"

COMMIT_SHA = "a" * 40
TREE_SHA = "b" * 40

FILE_PATH = "README.md"
FILE_CONTENT = b"# JAS-SI\nVerified evidence.\n"

def git_blob_sha(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()

class FakeGitHubResponse:

    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload

class TestGitHubEvidenceAPI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        store = JsonlSecurityEventStore(
            Path(self.temp_dir.name) / "security-events.jsonl"
        )

        self.store_patch = patch.object(
            api,
            "_security_event_store",
            store,
        )
        self.store_patch.start()
        self.addCleanup(self.store_patch.stop)

        self.settings_patch = patch.object(
            api,
            "settings",
            replace(
                api.settings,
                api_enabled=True,
                api_key=TEST_API_KEY,
                rate_limit_requests=60,
                rate_limit_window_seconds=60,
            ),
        )
        self.settings_patch.start()
        self.addCleanup(self.settings_patch.stop)

        with api._rate_limit_lock:
            api._rate_limit_buckets.clear()

        self.client = TestClient(api.app)

        self.headers = {
            "X-API-Key": TEST_API_KEY,
        }

        self.payload = {
            "repository": "owner/project",
            "commit_sha": COMMIT_SHA,
            "paths": [FILE_PATH],
        }

    def commit_response(self):
        return FakeGitHubResponse(
            200,
            {
                "sha": COMMIT_SHA,
                "commit": {
                    "tree": {
                        "sha": TREE_SHA,
                    }
                },
            },
        )

    def file_response(self, content=FILE_CONTENT, sha=None):
        return FakeGitHubResponse(
            200,
            {
                "type": "file",
                "encoding": "base64",
                "content": base64.b64encode(content).decode("ascii"),
                "sha": sha or git_blob_sha(content),
            },
        )

    def perform_verification(self, mock_get):
        return self.client.post(
            "/v1/github/evidence",
            headers=self.headers,
            json=self.payload,
        )

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_valid_github_evidence(self, mock_get):
        mock_get.side_effect = [
            self.commit_response(),
            self.file_response(),
        ]

        response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 200)

        data = response.json()

        self.assertEqual(
            data["status"],
            "EVIDENCE_INTEGRITY_VERIFIED",
        )
        self.assertEqual(data["commit_sha"], COMMIT_SHA)
        self.assertEqual(data["tree_sha"], TREE_SHA)
        self.assertEqual(data["files_verified"], 1)

        self.assertEqual(
            data["files"][0]["integrity"],
            "VERIFIED",
        )

        self.assertEqual(
            data["files"][0]["blob_sha"],
            git_blob_sha(FILE_CONTENT),
        )

        self.assertEqual(
            data["files"][0]["sha256"],
            hashlib.sha256(FILE_CONTENT).hexdigest(),
        )

        self.assertTrue(data["read_only"])
        self.assertFalse(data["semantic_truth_verified"])

        self.assertEqual(mock_get.call_count, 2)

        for call in mock_get.call_args_list:
            self.assertFalse(
                call.kwargs["follow_redirects"]
            )

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_base64_content_with_newlines_is_verified(self, mock_get):
        encoded = base64.b64encode(FILE_CONTENT).decode("ascii")
        wrapped = encoded[:8] + "\n" + encoded[8:]

        file_response = FakeGitHubResponse(
            200,
            {
                "type": "file",
                "encoding": "base64",
                "content": wrapped,
                "sha": git_blob_sha(FILE_CONTENT),
            },
        )

        mock_get.side_effect = [
            self.commit_response(),
            file_response,
        ]

        response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["files"][0]["integrity"],
            "VERIFIED",
        )

    def test_missing_api_key_is_rejected(self):
        response = self.client.post(
            "/v1/github/evidence",
            json=self.payload,
        )

        self.assertEqual(response.status_code, 401)

    def test_invalid_commit_sha_is_rejected(self):
        payload = dict(self.payload)
        payload["commit_sha"] = "invalid"

        response = self.client.post(
            "/v1/github/evidence",
            headers=self.headers,
            json=payload,
        )

        self.assertEqual(response.status_code, 422)

    def test_extra_request_fields_are_rejected(self):
        payload = dict(self.payload)
        payload["unexpected"] = "value"

        response = self.client.post(
            "/v1/github/evidence",
            headers=self.headers,
            json=payload,
        )

        self.assertEqual(response.status_code, 422)

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_blob_tampering_is_rejected(self, mock_get):
        mock_get.side_effect = [
            self.commit_response(),
            self.file_response(
                content=FILE_CONTENT,
                sha="0" * 40,
            ),
        ]

        response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 422)
        self.assertIn("integrity", response.text.lower())

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_missing_github_commit_returns_404(self, mock_get):
        mock_get.return_value = FakeGitHubResponse(
            404,
            {"message": "Not Found"},
        )

        response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 404)

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_github_rate_limit_fails_closed(self, mock_get):
        mock_get.return_value = FakeGitHubResponse(
            403,
            {"message": "API rate limit exceeded"},
        )

        response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 503)

    def test_invalid_repository_is_rejected(self):
        payload = dict(self.payload)
        payload["repository"] = "https://example.com/repo"

        response = self.client.post(
            "/v1/github/evidence",
            headers=self.headers,
            json=payload,
        )

        self.assertEqual(response.status_code, 422)

    def test_path_traversal_is_rejected(self):
        payload = dict(self.payload)
        payload["paths"] = ["../secrets.txt"]

        response = self.client.post(
            "/v1/github/evidence",
            headers=self.headers,
            json=payload,
        )

        self.assertEqual(response.status_code, 422)

    def test_duplicate_paths_are_rejected(self):
        payload = dict(self.payload)
        payload["paths"] = [
            "README.md",
            "README.md",
        ]

        response = self.client.post(
            "/v1/github/evidence",
            headers=self.headers,
            json=payload,
        )

        self.assertEqual(response.status_code, 422)

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_malformed_base64_is_rejected(self, mock_get):
        invalid_response = FakeGitHubResponse(
            200,
            {
                "type": "file",
                "encoding": "base64",
                "content": "%%%INVALID_BASE64%%%",
                "sha": "0" * 40,
            },
        )

        mock_get.side_effect = [
            self.commit_response(),
            invalid_response,
        ]

        response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 502)
        self.assertIn("Base64", response.text)

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_oversized_payload_is_rejected_before_base64_decode(
        self,
        mock_get,
    ):
        oversized_content = b"A" * (
            verify_router._MAX_FILE_BYTES + 1
        )

        encoded = base64.b64encode(
            oversized_content
        ).decode("ascii")

        file_response = FakeGitHubResponse(
            200,
            {
                "type": "file",
                "encoding": "base64",
                "content": encoded,
                "sha": git_blob_sha(oversized_content),
            },
        )

        mock_get.side_effect = [
            self.commit_response(),
            file_response,
        ]

        with patch(
            "jas_si_agent.verify_router.base64.b64decode",
            wraps=base64.b64decode,
        ) as mock_decode:

            response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 413)
        mock_decode.assert_not_called()

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_github_timeout_returns_504(self, mock_get):
        mock_get.side_effect = httpx.TimeoutException(
            "simulated timeout"
        )

        response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 504)
        self.assertNotIn("simulated timeout", response.text)

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_github_connection_error_returns_502(self, mock_get):
        mock_get.side_effect = httpx.ConnectError(
            "simulated connection failure"
        )

        response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 502)
        self.assertNotIn(
            "simulated connection failure",
            response.text,
        )

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_unexpected_github_status_returns_502(self, mock_get):
        mock_get.return_value = FakeGitHubResponse(
            500,
            {"message": "Internal Server Error"},
        )

        response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 502)

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_unexpected_commit_sha_is_rejected(self, mock_get):
        bad_commit = FakeGitHubResponse(
            200,
            {
                "sha": "c" * 40,
                "commit": {
                    "tree": {
                        "sha": TREE_SHA,
                    }
                },
            },
        )

        mock_get.return_value = bad_commit

        response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 502)

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_invalid_github_json_is_rejected(self, mock_get):
        class InvalidJsonResponse:
            status_code = 200

            def json(self):
                raise ValueError("invalid JSON")

        mock_get.return_value = InvalidJsonResponse()

        response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 502)

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_non_file_github_resource_is_rejected(self, mock_get):
        directory_response = FakeGitHubResponse(
            200,
            {
                "type": "dir",
                "encoding": "none",
            },
        )

        mock_get.side_effect = [
            self.commit_response(),
            directory_response,
        ]

        response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 422)

    @patch("jas_si_agent.verify_router.httpx.get")
    def test_unsupported_github_encoding_is_rejected(self, mock_get):
        unsupported_response = FakeGitHubResponse(
            200,
            {
                "type": "file",
                "encoding": "utf-8",
                "content": "plain text",
                "sha": "0" * 40,
            },
        )

        mock_get.side_effect = [
            self.commit_response(),
            unsupported_response,
        ]

        response = self.perform_verification(mock_get)

        self.assertEqual(response.status_code, 422)

if __name__ == "__main__":
    unittest.main()
