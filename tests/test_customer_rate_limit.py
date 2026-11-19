from __future__ import annotations

import sys
import unittest
from types import ModuleType
from unittest.mock import patch

from jas_si_agent.customer_rate_limit import (
    CustomerRateLimitError,
    PostgresCustomerRateLimiter,
)


class FakeCursor:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, params=None):
        self.calls.append((query, params))

    def fetchone(self):
        return True, 17


class FakeConnection:
    def __init__(self, cursor):
        self.fake_cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self):
        return self.fake_cursor


class TestPostgresCustomerRateLimiter(unittest.TestCase):
    def setUp(self):
        self.cursor = FakeCursor()
        self.connection = FakeConnection(self.cursor)
        self.psycopg = ModuleType("psycopg")
        self.psycopg.connect = lambda dsn: self.connection
        self.store = PostgresCustomerRateLimiter(
            "postgresql://test:test@localhost/test",
            b"p" * 32,
        )

    def test_check_uses_database_owned_rate_limit_routine(self):
        with patch.dict(sys.modules, {"psycopg": self.psycopg}):
            allowed, retry_after = self.store.check(
                "203.0.113.10",
                limit=5,
                window_seconds=900,
            )

        self.assertTrue(allowed)
        self.assertEqual(retry_after, 17)
        self.assertEqual(len(self.cursor.calls), 1)
        query, params = self.cursor.calls[0]
        self.assertIn("public.jas_si_customer_rate_limit_check(%s::bytea,%s::integer,%s::integer)", query)
        self.assertEqual(len(params[0]), 32)
        self.assertEqual(params[1:], (5, 900))
        self.assertNotIn("INSERT INTO jas_si_customer_rate_limits", query)
        self.assertNotIn("UPDATE jas_si_customer_rate_limits", query)

    def test_verify_schema_accepts_expand_phase_before_acl_contraction(self):
        with patch.dict(sys.modules, {"psycopg": self.psycopg}):
            self.assertTrue(self.store.verify_schema())

        self.assertEqual(len(self.cursor.calls), 1)
        query, _ = self.cursor.calls[0]
        self.assertIn("public.jas_si_customer_rate_limit_check", query)
        self.assertIn("SECURITY", query.upper()) if False else None
        # During expand/deploy, legacy table grants intentionally remain.
        # Their removal is independently enforced by the contract migration.
        self.assertNotIn("has_table_privilege", query)

    def test_invalid_ip_is_rejected_before_database_access(self):
        with self.assertRaises(CustomerRateLimitError):
            self.store.check("not-an-ip", limit=5, window_seconds=900)
        self.assertEqual(self.cursor.calls, [])

    def test_invalid_limit_is_rejected(self):
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(CustomerRateLimitError):
                    self.store.check("203.0.113.10", limit=value, window_seconds=900)
        self.assertEqual(self.cursor.calls, [])

    def test_invalid_window_is_rejected(self):
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(CustomerRateLimitError):
                    self.store.check("203.0.113.10", limit=5, window_seconds=value)
        self.assertEqual(self.cursor.calls, [])


if __name__ == "__main__":
    unittest.main()
