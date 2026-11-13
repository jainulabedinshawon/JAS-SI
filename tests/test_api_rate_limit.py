from __future__ import annotations

import hashlib
import hmac
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from dataclasses import replace
from jas_si_agent import api
from jas_si_agent.api_rate_limit import ApiRateLimitError, PostgresApiRateLimiter


class TestPostgresApiRateLimiter(unittest.TestCase):
    def test_preview_startup_requires_dedicated_shared_limiter_pepper(self):
        deployed_settings = replace(
            api.settings,
            environment="preview",
            api_enabled=True,
            api_key_pepper=b"api-key-pepper-test-value-32-bytes",
            database_url="postgresql://staging-runtime",
            api_rate_limit_pepper=None,
        )
        with patch.object(api, "settings", deployed_settings):
            with self.assertRaisesRegex(
                RuntimeError, "requires JAS_SI_API_RATE_LIMIT_PEPPER"
            ):
                api.initialize_security_event_store()

    def setUp(self):
        self.pepper = b"test-api-rate-limit-pepper-32-bytes-minimum"
        self.limiter = PostgresApiRateLimiter(
            "postgresql://rate-limit-test", self.pepper
        )

    def test_bucket_key_is_keyed_and_namespaced_without_persisting_raw_ip(self):
        ip = "2001:0db8::1"
        expected = hmac.new(
            self.pepper,
            b"jas-si/api-rate-limit/v1:2001:db8::1",
            hashlib.sha256,
        ).digest()
        key = self.limiter._bucket_key(ip)
        self.assertEqual(key, expected)
        self.assertEqual(len(key), 32)
        self.assertNotIn(ip.encode(), key)

    def test_invalid_ip_is_rejected_before_database_access(self):
        with self.assertRaises(ApiRateLimitError):
            self.limiter._bucket_key("not-an-ip")

    def test_check_uses_atomic_database_routine_and_returns_decision(self):
        cursor = MagicMock()
        cursor.fetchone.return_value = (False, 0, 17)
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.cursor.return_value.__enter__.return_value = cursor
        fake_psycopg = SimpleNamespace(connect=MagicMock(return_value=connection))
        with patch.dict(sys.modules, {"psycopg": fake_psycopg}):
            result = self.limiter.check(
                "203.0.113.10", limit=60, window_seconds=60
            )
        self.assertEqual(result, (False, 0, 17))
        query, params = cursor.execute.call_args.args
        self.assertIn("jas_si_api_rate_limit_check", query)
        self.assertEqual(params[1:], (60, 60))
        self.assertEqual(len(params[0]), 32)
        self.assertNotIn("203.0.113.10", repr(params))

    def test_database_failure_is_not_downgraded(self):
        fake_psycopg = SimpleNamespace(
            connect=MagicMock(side_effect=OSError("database unavailable"))
        )
        with patch.dict(sys.modules, {"psycopg": fake_psycopg}):
            with self.assertRaisesRegex(ApiRateLimitError, "Shared API"):
                self.limiter.check("203.0.113.10", limit=10, window_seconds=60)

    def test_invalid_limits_are_rejected(self):
        with self.assertRaises(ApiRateLimitError):
            self.limiter.check("203.0.113.10", limit=0, window_seconds=60)
        with self.assertRaises(ApiRateLimitError):
            self.limiter.check("203.0.113.10", limit=10, window_seconds=0)

    def test_short_pepper_is_rejected(self):
        with self.assertRaises(ApiRateLimitError):
            PostgresApiRateLimiter("postgresql://test", b"short")


if __name__ == "__main__":
    unittest.main()
