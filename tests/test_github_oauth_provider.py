"""No-network contract tests for the GitHub OAuth provider client."""
from __future__ import annotations

import unittest
from urllib.parse import parse_qs

import httpx

from jas_si_agent.github_oauth_provider import (
    GitHubOAuthProvider,
    GitHubOAuthProviderError,
)


class GitHubOAuthProviderTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.access_token = "gho_" + "A" * 36

        def handler(request):
            self.requests.append(request)
            if request.url.path == "/login/oauth/access_token":
                return httpx.Response(200, json={
                    "access_token": self.access_token,
                    "token_type": "bearer",
                    "scope": "",
                })
            if request.url.path == "/user":
                return httpx.Response(200, json={
                    "id": 123456, "login": "jas-user", "name": "JAS User"
                })
            return httpx.Response(404, json={"message": "not found"})

        self.transport = httpx.MockTransport(handler)
        self.provider = GitHubOAuthProvider(
            client_id="Iv1.example", client_secret="secret-" + "S" * 32,
            transport=self.transport,
        )

    def test_exchange_sends_pkce_and_user_lookup_verifies_identity(self):
        token = self.provider.exchange_code(
            code="authorization-code", code_verifier="V" * 43,
            redirect_uri="https://jas-si.example.test/oauth/callback",
        )
        self.assertNotIn(self.access_token, repr(token))
        user = self.provider.authenticated_user(token)
        self.assertEqual(user.github_user_id, 123456)
        self.assertEqual(user.login, "jas-user")
        self.assertEqual(len(self.requests), 2)
        form = parse_qs(self.requests[0].content.decode("ascii"))
        self.assertEqual(form["code_verifier"], ["V" * 43])
        self.assertEqual(form["redirect_uri"], ["https://jas-si.example.test/oauth/callback"])
        self.assertEqual(
            self.requests[1].headers["Authorization"],
            "Bearer " + self.access_token,
        )

    def test_provider_error_is_rejected_without_exposing_body(self):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"error": "bad_verification_code", "error_description": "secret detail"}
            )
        )
        provider = GitHubOAuthProvider(
            client_id="Iv1.example", client_secret="secret-" + "S" * 32,
            transport=transport,
        )
        with self.assertRaises(GitHubOAuthProviderError) as raised:
            provider.exchange_code(
                code="authorization-code", code_verifier="V" * 43,
                redirect_uri="https://jas-si.example.test/oauth/callback",
            )
        self.assertNotIn("secret detail", str(raised.exception))

    def test_non_bearer_or_malformed_token_is_rejected(self):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"access_token": "not-a-token", "token_type": "basic"}
            )
        )
        provider = GitHubOAuthProvider(
            client_id="Iv1.example", client_secret="secret-" + "S" * 32,
            transport=transport,
        )
        with self.assertRaises(GitHubOAuthProviderError):
            provider.exchange_code(
                code="authorization-code", code_verifier="V" * 43,
                redirect_uri="https://jas-si.example.test/oauth/callback",
            )

    def test_redirect_responses_are_not_followed(self):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(302, headers={"Location": "https://attacker.test"})
        )
        provider = GitHubOAuthProvider(
            client_id="Iv1.example", client_secret="secret-" + "S" * 32,
            transport=transport,
        )
        with self.assertRaises(GitHubOAuthProviderError):
            provider.exchange_code(
                code="authorization-code", code_verifier="V" * 43,
                redirect_uri="https://jas-si.example.test/oauth/callback",
            )

    def test_user_identity_response_must_be_well_formed(self):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"id": True, "login": "not valid login"}
            )
        )
        provider = GitHubOAuthProvider(
            client_id="Iv1.example", client_secret="secret-" + "S" * 32,
            transport=transport,
        )
        token = provider.exchange_code(
            code="authorization-code", code_verifier="V" * 43,
            redirect_uri="https://jas-si.example.test/oauth/callback",
        )
        with self.assertRaises(GitHubOAuthProviderError):
            provider.authenticated_user(token)


if __name__ == "__main__":
    unittest.main(verbosity=2)
