"""Unit tests for customer identity normalization and token handling."""
from __future__ import annotations

import unittest
from datetime import timedelta

from jas_si_agent.customer_identity import (
    CustomerIdentityError,
    PostgresCustomerIdentityStore,
    normalize_email,
    normalize_organization_name,
)


class TestCustomerIdentityPrimitives(unittest.TestCase):
    def test_email_is_normalized(self):
        self.assertEqual(normalize_email("  USER@Example.Test "), "user@example.test")

    def test_invalid_email_is_rejected(self):
        for value in ("", "missing-at.example.test", "two@@example.test", "a" * 255):
            with self.subTest(value=value):
                with self.assertRaises(CustomerIdentityError):
                    normalize_email(value)

    def test_organization_name_is_trimmed_and_collapsed(self):
        self.assertEqual(
            normalize_organization_name("  Example   Research   Lab "),
            "Example Research Lab",
        )

    def test_invalid_organization_name_is_rejected(self):
        for value in ("", "   ", "x" * 161):
            with self.subTest(value=value):
                with self.assertRaises(CustomerIdentityError):
                    normalize_organization_name(value)

    def test_token_digest_is_keyed_and_never_raw(self):
        store = PostgresCustomerIdentityStore(
            "postgresql://unused", b"customer-identity-test-pepper-32-bytes-minimum"
        )
        token = "one-time-token-value-that-is-long-enough"
        digest = store._digest(token)
        self.assertEqual(len(digest), 32)
        self.assertNotEqual(digest, token.encode("utf-8"))
        self.assertEqual(digest, store._digest(token))

    def test_rejects_short_pepper_and_nonpositive_ttl(self):
        with self.assertRaises(CustomerIdentityError):
            PostgresCustomerIdentityStore("postgresql://unused", b"short")
        with self.assertRaises(CustomerIdentityError):
            PostgresCustomerIdentityStore(
                "postgresql://unused",
                b"customer-identity-test-pepper-32-bytes-minimum",
                session_ttl=timedelta(seconds=0),
            )


if __name__ == "__main__":
    unittest.main()
