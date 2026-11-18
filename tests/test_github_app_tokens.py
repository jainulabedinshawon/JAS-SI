from __future__ import annotations

import base64
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from jas_si_agent.github_app_tokens import (
    GitHubAppInstallationTokenIssuer,
    GitHubAppTokenError,
    GitHubAppTokenSettings,
    IssuedGitHubInstallationToken,
    _READ_ONLY_PERMISSIONS,
)


class GitHubAppTokenIssuerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.key_path = Path(self.temp.name) / "app.pem"
        self.key_path.write_bytes(self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        self.now = 1_800_000_000
        self.settings = GitHubAppTokenSettings(app_id=5818164, private_key_path=str(self.key_path))

    def _response(self, *, repository="jainulabedinshawon/JAS-SI", permissions=None, expires=None):
        return {
            "token": "ghs-short-lived-test-token",
            "expires_at": expires or datetime.fromtimestamp(self.now + 3600, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "repositories": [{"full_name": repository}],
            "permissions": permissions or dict(_READ_ONLY_PERMISSIONS),
        }

    def _issuer(self, response, *, status=201):
        def handler(request):
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.url.path, "/app/installations/183349938/access_tokens")
            self.assertEqual(request.headers["X-GitHub-Api-Version"], "2022-11-28")
            self.assertEqual(request.headers["Accept"], "application/vnd.github+json")
            body = json.loads(request.content)
            self.assertEqual(body["repositories"], ["JAS-SI"])
            self.assertEqual(body["permissions"], _READ_ONLY_PERMISSIONS)
            jwt = request.headers["Authorization"].removeprefix("Bearer ")
            header, payload, signature = jwt.split(".")
            decoded_header = json.loads(base64.urlsafe_b64decode(header + "=="))
            decoded_payload = json.loads(base64.urlsafe_b64decode(payload + "=="))
            self.assertEqual(decoded_header, {"alg": "RS256", "typ": "JWT"})
            self.assertEqual(decoded_payload, {"iss": "5818164", "iat": self.now - 60, "exp": self.now + 540})
            self.key.public_key().verify(
                base64.urlsafe_b64decode(signature + "=="),
                f"{header}.{payload}".encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return httpx.Response(status, json=response)
        client = httpx.Client(transport=httpx.MockTransport(handler))
        return GitHubAppInstallationTokenIssuer(self.settings, http_client=client, clock=lambda: self.now)

    def test_mints_one_repository_read_only_token_with_verified_jwt(self):
        issuer = self._issuer(self._response())
        result = issuer.issue(installation_id=183349938, repository="jainulabedinshawon/JAS-SI")
        self.assertEqual(result.installation_id, 183349938)
        self.assertEqual(result.repository, "jainulabedinshawon/JAS-SI")
        self.assertEqual(result.access_token, "ghs-short-lived-test-token")
        self.assertNotIn(result.access_token, repr(result))

    def test_rejects_wrong_repository_scope(self):
        issuer = self._issuer(self._response(repository="someone/other"))
        with self.assertRaises(GitHubAppTokenError):
            issuer.issue(installation_id=183349938, repository="jainulabedinshawon/JAS-SI")

    def test_rejects_overbroad_permissions(self):
        permissions = dict(_READ_ONLY_PERMISSIONS)
        permissions["contents"] = "write"
        issuer = self._issuer(self._response(permissions=permissions))
        with self.assertRaises(GitHubAppTokenError):
            issuer.issue(installation_id=183349938, repository="jainulabedinshawon/JAS-SI")

    def test_rejects_expired_token(self):
        expired = (datetime.fromtimestamp(self.now - 1, timezone.utc)
                   .replace(microsecond=0).isoformat().replace("+00:00", "Z"))
        issuer = self._issuer(self._response(expires=expired))
        with self.assertRaises(GitHubAppTokenError):
            issuer.issue(installation_id=183349938, repository="jainulabedinshawon/JAS-SI")

    def test_redacts_api_failure(self):
        issuer = self._issuer({"message": "private detail"}, status=401)
        with self.assertRaisesRegex(GitHubAppTokenError, "HTTP 401") as raised:
            issuer.issue(installation_id=183349938, repository="jainulabedinshawon/JAS-SI")
        self.assertNotIn("private detail", str(raised.exception))

    def test_rejects_invalid_installation_or_repository(self):
        issuer = self._issuer(self._response())
        for installation_id, repository in ((0, "jainulabedinshawon/JAS-SI"), (True, "jainulabedinshawon/JAS-SI"), (1, "../repo")):
            with self.subTest(installation_id=installation_id, repository=repository):
                with self.assertRaises(GitHubAppTokenError):
                    issuer.issue(installation_id=installation_id, repository=repository)

    def test_settings_require_official_github_api_and_valid_timeout(self):
        with self.assertRaises(ValueError):
            GitHubAppTokenSettings(app_id=1, private_key_path=str(self.key_path), api_base_url="http://example.com")
        with self.assertRaises(ValueError):
            GitHubAppTokenSettings(app_id=1, private_key_path=str(self.key_path), timeout_seconds=60)

    def test_token_model_hides_secret(self):
        token = IssuedGitHubInstallationToken(
            installation_id=1,
            repository="owner/repo",
            access_token="secret-token",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        )
        self.assertNotIn("secret-token", repr(token))


if __name__ == "__main__":
    unittest.main()
