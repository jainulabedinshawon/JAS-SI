from __future__ import annotations

import hashlib
import unittest
from urllib.parse import parse_qs, urlsplit

from jas_si_agent.github_oauth import (
    GitHubOAuthError,
    build_github_oauth_authorization_request,
    create_github_oauth_attempt,
    validate_github_oauth_callback,
)


class GitHubOAuthPKCETests(unittest.TestCase):
    def setUp(self):
        self.attempt = create_github_oauth_attempt()

    def test_attempt_has_high_entropy_state_and_pkce_s256(self):
        self.assertEqual(len(self.attempt.state), 43)
        self.assertEqual(len(self.attempt.state_digest), 32)
        self.assertEqual(len(self.attempt.code_verifier), 43)
        expected = __import__("base64").urlsafe_b64encode(
            hashlib.sha256(self.attempt.code_verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        self.assertEqual(self.attempt.code_challenge, expected)
        self.assertEqual(self.attempt.code_challenge_method, "S256")

    def test_authorization_url_contains_required_pkce_and_state(self):
        request = build_github_oauth_authorization_request(
            client_id="Iv1.exampleClient",
            redirect_uri="https://jas-si.example.com/v1/github/oauth/callback",
            attempt=self.attempt,
        )
        parsed = urlsplit(request.authorization_url)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "github.com")
        self.assertEqual(parsed.path, "/login/oauth/authorize")
        query = parse_qs(parsed.query)
        self.assertEqual(query["client_id"], ["Iv1.exampleClient"])
        self.assertEqual(query["state"], [self.attempt.state])
        self.assertEqual(query["code_challenge"], [self.attempt.code_challenge])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["redirect_uri"], ["https://jas-si.example.com/v1/github/oauth/callback"])
        self.assertEqual(request.state_digest, self.attempt.state_digest)
        self.assertEqual(request.code_verifier, self.attempt.code_verifier)

    def test_callback_accepts_matching_state_digest_and_code(self):
        result = validate_github_oauth_callback(
            supplied_state=self.attempt.state,
            expected_state_digest=self.attempt.state_digest,
            authorization_code="github-auth-code",
        )
        self.assertEqual(result, "github-auth-code")

    def test_callback_rejects_state_replay_or_cross_attempt_state(self):
        other = create_github_oauth_attempt()
        with self.assertRaises(GitHubOAuthError):
            validate_github_oauth_callback(
                supplied_state=self.attempt.state,
                expected_state_digest=other.state_digest,
                authorization_code="github-auth-code",
            )

    def test_callback_rejects_malformed_state_and_code(self):
        for state, digest, code in (
            ("bad", self.attempt.state_digest, "valid-code"),
            (self.attempt.state, b"short", "valid-code"),
            (self.attempt.state, self.attempt.state_digest, ""),
            (self.attempt.state, self.attempt.state_digest, "bad code"),
        ):
            with self.subTest(state=state, code=code):
                with self.assertRaises(GitHubOAuthError):
                    validate_github_oauth_callback(
                        supplied_state=state,
                        expected_state_digest=digest,
                        authorization_code=code,
                    )

    def test_rejects_insecure_or_ambiguous_redirect_uris(self):
        for uri in (
            "http://jas-si.example.com/callback",
            "https://user:pass@jas-si.example.com/callback",
            "https://jas-si.example.com:444/callback",
            "https://jas-si.example.com/callback#fragment",
            "https:///callback",
        ):
            with self.subTest(uri=uri):
                with self.assertRaises(GitHubOAuthError):
                    build_github_oauth_authorization_request(
                        client_id="Iv1.exampleClient",
                        redirect_uri=uri,
                        attempt=self.attempt,
                    )

    def test_rejects_invalid_client_id_and_tampered_pkce_attempt(self):
        with self.assertRaises(GitHubOAuthError):
            build_github_oauth_authorization_request(
                client_id="bad client id",
                redirect_uri="https://jas-si.example.com/callback",
                attempt=self.attempt,
            )
        from dataclasses import replace
        tampered = replace(self.attempt, code_challenge="A" * 43)
        with self.assertRaises(GitHubOAuthError):
            build_github_oauth_authorization_request(
                client_id="Iv1.exampleClient",
                redirect_uri="https://jas-si.example.com/callback",
                attempt=tampered,
            )

    def test_secret_material_is_redacted_from_repr(self):
        request = build_github_oauth_authorization_request(
            client_id="Iv1.exampleClient",
            redirect_uri="https://jas-si.example.com/callback",
            attempt=self.attempt,
        )
        for secret in (self.attempt.state, self.attempt.code_verifier, request.authorization_url):
            self.assertNotIn(secret, repr(self.attempt))
            self.assertNotIn(secret, repr(request))


if __name__ == "__main__":
    unittest.main()
