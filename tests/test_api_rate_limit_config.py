from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from jas_si_agent.config import Settings


class TestApiRateLimitConfig(unittest.TestCase):
    def test_dedicated_api_rate_limit_pepper_is_loaded(self):
        secret = "dedicated-api-rate-limit-pepper-at-least-32-bytes"
        with patch.dict(os.environ, {"JAS_SI_API_RATE_LIMIT_PEPPER": secret}, clear=True):
            settings = Settings.from_env()
        self.assertEqual(settings.api_rate_limit_pepper, secret.encode())
        self.assertNotIn(secret, repr(settings))

    def test_short_api_rate_limit_pepper_is_rejected(self):
        with patch.dict(os.environ, {"JAS_SI_API_RATE_LIMIT_PEPPER": "short"}, clear=True):
            with self.assertRaisesRegex(ValueError, "JAS_SI_API_RATE_LIMIT_PEPPER"):
                Settings.from_env()

    def test_customer_and_api_rate_limit_peppers_are_independent(self):
        with patch.dict(os.environ, {
            "JAS_SI_CUSTOMER_TOKEN_PEPPER": "customer-pepper-32-bytes-minimum-value",
            "JAS_SI_API_RATE_LIMIT_PEPPER": "api-rate-limit-pepper-32-bytes-minimum",
        }, clear=True):
            settings = Settings.from_env()
        self.assertNotEqual(
            settings.customer_token_pepper,
            settings.api_rate_limit_pepper,
        )


if __name__ == "__main__":
    unittest.main()
