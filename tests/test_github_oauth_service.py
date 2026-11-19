"""Service-level tests for persist-before-redirect and consume-before-decrypt."""
from __future__ import annotations

import hashlib
import unittest
import uuid
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

from jas_si_agent.customer_identity import CustomerAccount
from jas_si_agent.github_oauth_service import (
    GitHubOAuthService,
    GitHubOAuthServiceError,
)
from jas_si_agent.github_oauth_crypto import GitHubOAuthVerifierCipher


class FakeStore:
    def __init__(self):
        self.events = []
        self.attempt = None
        self.row = None
        self.session_secret = b"s" * 32

    def session_digest(self, token):
        if token != "S" * 43:
            raise GitHubOAuthServiceError("Invalid or expired customer session")
        return hashlib.sha256(self.session_secret).digest()

    def create(self, **kwargs):
        self.events.append("persist")
        self.attempt = kwargs

    def consume(self, **kwargs):
        self.events.append("consume")
        if self.row is None:
            return None
        return self.row


class GitHubOAuthServiceTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        self.key = b"k" * 32
        self.cipher = GitHubOAuthVerifierCipher(
            keys={"test-v1": self.key}, active_key_version="test-v1"
        )
        self.service = GitHubOAuthService(
            store=self.store, cipher=self.cipher,
            client_id="Iv1.testClient",
            redirect_uri="https://jas-si.example.test/v1/github/oauth/callback",
        )
        self.account = CustomerAccount(
            account_id=uuid.uuid4(), tenant_id=uuid.uuid4(),
            email="test@example.test", organization_name="Test Org",
            status="active",
        )
        self.session = "S" * 43

    def test_begin_persists_ciphertext_before_returning_redirect(self):
        url = self.service.begin(session_token=self.session, account=self.account, installation_id=98765)
        self.assertEqual(self.store.events, ["persist"])
        self.assertTrue(url.startswith("https://github.com/login/oauth/authorize?"))
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(query["state"][0] != "", True)
        self.assertEqual(len(self.store.attempt["state_digest"]), 32)
        self.assertNotIn("code_verifier", self.store.attempt)
        self.assertEqual(self.store.attempt["verifier_key_version"], "test-v1")
        self.assertNotIn(self.store.attempt["verifier_ciphertext"].decode("latin1"), url)

    def test_begin_rejects_inactive_account_without_persisting(self):
        inactive = CustomerAccount(
            account_id=self.account.account_id, tenant_id=self.account.tenant_id,
            email=self.account.email, organization_name=self.account.organization_name,
            status="suspended",
        )
        with self.assertRaises(GitHubOAuthServiceError):
            self.service.begin(session_token=self.session, account=inactive, installation_id=98765)
        self.assertEqual(self.store.events, [])

    def test_callback_consumes_before_decrypting_and_returns_bound_identity(self):
        url = self.service.begin(session_token=self.session, account=self.account, installation_id=98765)
        state = parse_qs(urlsplit(url).query)["state"][0]
        attempt_id = uuid.uuid4()
        verifier = "A" * 43
        envelope = self.cipher.encrypt(
            verifier, attempt_id=attempt_id,
            tenant_id=self.account.tenant_id, account_id=self.account.account_id,
            redirect_uri_digest=hashlib.sha256(
                b"https://jas-si.example.test/v1/github/oauth/callback"
            ).digest(),
        )
        self.store.row = (
            attempt_id, self.account.tenant_id, self.account.account_id,
            98765, envelope.ciphertext, envelope.key_version,
        )
        result = self.service.consume_callback(
            session_token=self.session, state=state,
            authorization_code="github-code",
        )
        self.assertEqual(self.store.events, ["persist", "consume"])
        self.assertEqual(result.attempt_id, attempt_id)
        self.assertEqual(result.tenant_id, self.account.tenant_id)
        self.assertEqual(result.account_id, self.account.account_id)
        self.assertEqual(result.installation_id, 98765)
        self.assertEqual(result.code_verifier, verifier)
        self.assertNotIn(verifier, repr(result))

    def test_callback_rejects_unknown_attempt(self):
        with self.assertRaises(GitHubOAuthServiceError):
            self.service.consume_callback(
                session_token=self.session, state="A" * 43,
                authorization_code="github-code",
            )
        self.assertEqual(self.store.events, ["consume"])

    def test_callback_rejects_wrong_customer_session(self):
        url = self.service.begin(session_token=self.session, account=self.account, installation_id=98765)
        state = parse_qs(urlsplit(url).query)["state"][0]
        with self.assertRaises(GitHubOAuthServiceError):
            self.service.consume_callback(
                session_token="X" * 43, state=state,
                authorization_code="github-code",
            )
        self.assertEqual(self.store.events, ["persist"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
