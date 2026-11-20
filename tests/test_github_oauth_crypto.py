"""Adversarial tests for tenant-bound GitHub OAuth PKCE verifier encryption."""
from __future__ import annotations

import unittest
import uuid

from jas_si_agent.github_oauth import create_github_oauth_attempt
from jas_si_agent.github_oauth_crypto import (
    EncryptedGitHubOAuthVerifier,
    GitHubOAuthEncryptionError,
    GitHubOAuthVerifierCipher,
)


class GitHubOAuthVerifierCipherTests(unittest.TestCase):
    def setUp(self):
        self.attempt_id = uuid.uuid4()
        self.tenant_id = uuid.uuid4()
        self.account_id = uuid.uuid4()
        self.redirect_digest = b"r" * 32
        self.verifier = create_github_oauth_attempt().code_verifier
        self.old_key = b"o" * 32
        self.new_key = b"n" * 32
        self.cipher = GitHubOAuthVerifierCipher(
            keys={"key-v1": self.old_key, "key-v2": self.new_key},
            active_key_version="key-v2",
        )

    def _encrypt(self):
        return self.cipher.encrypt(
            self.verifier,
            attempt_id=self.attempt_id,
            tenant_id=self.tenant_id,
            account_id=self.account_id,
            redirect_uri_digest=self.redirect_digest,
        )

    def _decrypt(self, envelope, **overrides):
        identity = {
            "attempt_id": self.attempt_id,
            "tenant_id": self.tenant_id,
            "account_id": self.account_id,
            "redirect_uri_digest": self.redirect_digest,
        }
        identity.update(overrides)
        return self.cipher.decrypt(envelope, **identity)

    def test_round_trip_uses_active_key_and_hides_ciphertext_from_repr(self):
        envelope = self._encrypt()
        self.assertEqual(envelope.key_version, "key-v2")
        self.assertEqual(self._decrypt(envelope), self.verifier)
        self.assertNotIn(envelope.ciphertext.hex(), repr(envelope))
        self.assertNotIn(self.verifier, repr(envelope))

    def test_ciphertext_is_randomized(self):
        first, second = self._encrypt(), self._encrypt()
        self.assertNotEqual(first.ciphertext, second.ciphertext)
        self.assertEqual(self._decrypt(first), self.verifier)
        self.assertEqual(self._decrypt(second), self.verifier)

    def test_tenant_account_attempt_and_redirect_are_authenticated(self):
        envelope = self._encrypt()
        for override in (
            {"tenant_id": uuid.uuid4()},
            {"account_id": uuid.uuid4()},
            {"attempt_id": uuid.uuid4()},
            {"redirect_uri_digest": b"x" * 32},
        ):
            with self.subTest(override=override):
                with self.assertRaises(GitHubOAuthEncryptionError):
                    self._decrypt(envelope, **override)

    def test_ciphertext_tampering_is_rejected(self):
        envelope = self._encrypt()
        damaged = bytearray(envelope.ciphertext)
        damaged[-1] ^= 1
        altered = EncryptedGitHubOAuthVerifier(bytes(damaged), envelope.key_version)
        with self.assertRaises(GitHubOAuthEncryptionError):
            self._decrypt(altered)

    def test_unknown_key_version_is_rejected(self):
        envelope = self._encrypt()
        altered = EncryptedGitHubOAuthVerifier(envelope.ciphertext, "retired-key")
        with self.assertRaises(GitHubOAuthEncryptionError):
            self._decrypt(altered)

    def test_old_key_remains_available_during_rotation(self):
        old_cipher = GitHubOAuthVerifierCipher(
            keys={"key-v1": self.old_key},
            active_key_version="key-v1",
        )
        old_envelope = old_cipher.encrypt(
            self.verifier,
            attempt_id=self.attempt_id,
            tenant_id=self.tenant_id,
            account_id=self.account_id,
            redirect_uri_digest=self.redirect_digest,
        )
        self.assertEqual(self._decrypt(old_envelope), self.verifier)

    def test_invalid_keyring_and_verifier_fail_closed(self):
        with self.assertRaises(GitHubOAuthEncryptionError):
            GitHubOAuthVerifierCipher(keys={"key-v1": b"short"}, active_key_version="key-v1")
        with self.assertRaises(GitHubOAuthEncryptionError):
            GitHubOAuthVerifierCipher(keys={"key-v1": self.old_key}, active_key_version="missing")
        with self.assertRaises(GitHubOAuthEncryptionError):
            self.cipher.encrypt(
                "not-a-pkce-verifier",
                attempt_id=self.attempt_id,
                tenant_id=self.tenant_id,
                account_id=self.account_id,
                redirect_uri_digest=self.redirect_digest,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
