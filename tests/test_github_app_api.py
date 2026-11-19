from __future__ import annotations

import base64
import json
import unittest
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from jas_si_agent.github_app_api import (
    GitHubAppAPIError,
    GitHubAppInstallationAPI,
)


class GitHubAppInstallationAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.private_key_pem = cls.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def _app(self, handler, **kwargs):
        return GitHubAppInstallationAPI(
            app_id=123456,
            private_key_pem=self.private_key_pem,
            transport=httpx.MockTransport(handler),
            clock=lambda: 1_800_000_000,
            **kwargs,
        )

    @staticmethod
    def _installation(installation_id=98765, app_id=123456, suspended_at=None):
        return {
            "id": installation_id,
            "app_id": app_id,
            "account": {"id": 4567, "login": "jas-test-org", "type": "Organization"},
            "suspended_at": suspended_at,
        }

    @staticmethod
    def _repo(repo_id, name):
        return {"id": repo_id, "full_name": name, "private": True}

    def test_app_jwt_is_rs256_short_lived_and_uses_app_id_issuer(self):
        api = self._app(lambda request: httpx.Response(404))
        token = api._app_jwt()
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        signature = base64.urlsafe_b64decode(signature_b64 + "==")
        self.assertEqual(header, {"alg": "RS256", "typ": "JWT"})
        self.assertEqual(payload, {"iat": 1_799_999_940, "exp": 1_800_000_540, "iss": 123456})
        self.private_key.public_key().verify(
            signature,
            f"{header_b64}.{payload_b64}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    def test_snapshot_uses_live_installation_and_full_repository_api(self):
        calls = []
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=45)).isoformat().replace("+00:00", "Z")

        def handler(request):
            calls.append((request.method, request.url.path, request.headers.get("authorization")))
            if request.url.path.endswith("/app/installations/98765"):
                return httpx.Response(200, json=self._installation())
            if request.url.path.endswith("/app/installations/98765/access_tokens"):
                self.assertEqual(request.method, "POST")
                self.assertTrue(request.headers["authorization"].startswith("Bearer "))
                return httpx.Response(201, json={"token": "ghs_" + "T" * 36, "expires_at": expiry})
            if request.url.path.endswith("/installation/repositories"):
                self.assertTrue(request.headers["authorization"].startswith("Bearer ghs_"))
                self.assertEqual(request.url.params["per_page"], "100")
                self.assertEqual(request.url.params["page"], "1")
                return httpx.Response(200, json={
                    "total_count": 2,
                    "repositories": [
                        self._repo(1, "jas-test-org/alpha"),
                        self._repo(2, "jas-test-org/beta"),
                    ],
                })
            return httpx.Response(404)

        snapshot = self._app(handler).snapshot(installation_id=98765)
        self.assertEqual(snapshot.installation_id, 98765)
        self.assertEqual(snapshot.app_id, 123456)
        self.assertEqual(snapshot.account_id, 4567)
        self.assertFalse(snapshot.suspended)
        self.assertEqual([r.full_name for r in snapshot.repositories], [
            "jas-test-org/alpha", "jas-test-org/beta"
        ])
        self.assertEqual(len(calls), 3)
        self.assertNotIn("ghs_" + "T" * 36, repr(snapshot))

    def test_repository_list_is_exhaustively_paginated(self):
        pages = []

        def handler(request):
            if request.url.path.endswith("/app/installations/98765"):
                return httpx.Response(200, json=self._installation())
            if request.url.path.endswith("/app/installations/98765/access_tokens"):
                return httpx.Response(201, json={
                    "token": "ghs_" + "A" * 36,
                    "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(),
                })
            if request.url.path.endswith("/installation/repositories"):
                page = int(request.url.params["page"])
                pages.append(page)
                repos = [self._repo(i, f"jas-test-org/repo-{i}") for i in range(1, 102)]
                return httpx.Response(200, json={
                    "total_count": 101,
                    "repositories": repos[(page - 1) * 100:page * 100],
                })
            return httpx.Response(404)

        snapshot = self._app(handler).snapshot(installation_id=98765)
        self.assertEqual(pages, [1, 2])
        self.assertEqual(len(snapshot.repositories), 101)

    def test_suspended_installation_never_mints_token_or_lists_repositories(self):
        def handler(request):
            if request.url.path.endswith("/app/installations/98765"):
                return httpx.Response(200, json=self._installation(suspended_at="2026-11-20T00:00:00Z"))
            self.fail(f"Unexpected request to {request.url.path}")

        snapshot = self._app(handler).snapshot(installation_id=98765)
        self.assertTrue(snapshot.suspended)
        self.assertEqual(snapshot.repositories, ())

    def test_deleted_installation_returns_none(self):
        api = self._app(lambda request: httpx.Response(404))
        self.assertIsNone(api.snapshot(installation_id=98765))

    def test_app_mismatch_fails_closed(self):
        def handler(request):
            return httpx.Response(200, json=self._installation(app_id=999999))
        with self.assertRaises(GitHubAppAPIError):
            self._app(handler).snapshot(installation_id=98765)

    def test_incomplete_or_changed_repository_pagination_fails_closed(self):
        def handler(request):
            if request.url.path.endswith("/app/installations/98765"):
                return httpx.Response(200, json=self._installation())
            if request.url.path.endswith("/app/installations/98765/access_tokens"):
                return httpx.Response(201, json={
                    "token": "ghs_" + "B" * 36,
                    "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(),
                })
            if request.url.path.endswith("/installation/repositories"):
                page = int(request.url.params["page"])
                return httpx.Response(200, json={
                    "total_count": 101 if page == 1 else 102,
                    "repositories": [self._repo(i, f"jas-test-org/r{i}") for i in range(1, 101)]
                    if page == 1 else [self._repo(101, "jas-test-org/r101")],
                })
            return httpx.Response(404)
        with self.assertRaises(GitHubAppAPIError):
            self._app(handler).snapshot(installation_id=98765)

    def test_duplicate_repository_identity_fails_closed(self):
        def handler(request):
            if request.url.path.endswith("/app/installations/98765"):
                return httpx.Response(200, json=self._installation())
            if request.url.path.endswith("/app/installations/98765/access_tokens"):
                return httpx.Response(201, json={
                    "token": "ghs_" + "C" * 36,
                    "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(),
                })
            if request.url.path.endswith("/installation/repositories"):
                return httpx.Response(200, json={
                    "total_count": 2,
                    "repositories": [
                        self._repo(1, "jas-test-org/alpha"),
                        self._repo(1, "jas-test-org/ALPHA"),
                    ],
                })
            return httpx.Response(404)
        with self.assertRaises(GitHubAppAPIError):
            self._app(handler).snapshot(installation_id=98765)

    def test_invalid_private_key_and_installation_id_rejected(self):
        with self.assertRaises(ValueError):
            GitHubAppInstallationAPI(app_id=123456, private_key_pem=b"not a key")
        api = self._app(lambda request: httpx.Response(404))
        for value in (0, -1, True, "98765"):
            with self.subTest(value=value), self.assertRaises(GitHubAppAPIError):
                api.snapshot(installation_id=value)


if __name__ == "__main__":
    unittest.main()
