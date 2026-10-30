
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.config import Settings


class TestTrustedAnchorEnvironmentConfig(unittest.TestCase):
    def test_missing_anchor_credentials_are_allowed(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings.from_env()

        self.assertIsNone(settings.trusted_anchor_hmac_secret)
        self.assertIsNone(settings.trusted_anchor_provider_id)

    def test_valid_anchor_credentials_are_loaded(self) -> None:
        secret = "test-secret-with-at-least-32-bytes-long"

        with patch.dict(
            os.environ,
            {
                "JAS_SI_TRUSTED_ANCHOR_HMAC_SECRET": secret,
                "JAS_SI_TRUSTED_ANCHOR_PROVIDER_ID": "test-provider",
            },
            clear=True,
        ):
            settings = Settings.from_env()

        self.assertEqual(
            settings.trusted_anchor_hmac_secret,
            secret.encode("utf-8"),
        )
        self.assertEqual(
            settings.trusted_anchor_provider_id,
            "test-provider",
        )

    def test_short_secret_is_rejected(self) -> None:
        with patch.dict(
            os.environ,
            {
                "JAS_SI_TRUSTED_ANCHOR_HMAC_SECRET": "too-short",
                "JAS_SI_TRUSTED_ANCHOR_PROVIDER_ID": "test-provider",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "at least 32 UTF-8 bytes",
            ):
                Settings.from_env()

    def test_secret_without_provider_id_is_rejected(self) -> None:
        with patch.dict(
            os.environ,
            {
                "JAS_SI_TRUSTED_ANCHOR_HMAC_SECRET":
                    "test-secret-with-at-least-32-bytes-long",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "must be configured together",
            ):
                Settings.from_env()

    def test_provider_id_without_secret_is_rejected(self) -> None:
        with patch.dict(
            os.environ,
            {
                "JAS_SI_TRUSTED_ANCHOR_PROVIDER_ID": "test-provider",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "must be configured together",
            ):
                Settings.from_env()

    def test_provider_id_with_surrounding_whitespace_is_rejected(self) -> None:
        with patch.dict(
            os.environ,
            {
                "JAS_SI_TRUSTED_ANCHOR_HMAC_SECRET":
                    "test-secret-with-at-least-32-bytes-long",
                "JAS_SI_TRUSTED_ANCHOR_PROVIDER_ID": " test-provider ",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "surrounding whitespace",
            ):
                Settings.from_env()

    def test_secret_is_not_exposed_in_settings_repr(self) -> None:
        secret = "test-secret-with-at-least-32-bytes-long"

        with patch.dict(
            os.environ,
            {
                "JAS_SI_TRUSTED_ANCHOR_HMAC_SECRET": secret,
                "JAS_SI_TRUSTED_ANCHOR_PROVIDER_ID": "test-provider",
            },
            clear=True,
        ):
            settings = Settings.from_env()

        self.assertNotIn(secret, repr(settings))


if __name__ == "__main__":
    unittest.main()
