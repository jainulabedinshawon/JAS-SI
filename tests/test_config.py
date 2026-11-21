
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

    def test_github_capability_workload_identity_registry_is_optional(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings.from_env()
        self.assertIsNone(settings.github_capability_workload_identities)

    def test_github_capability_workload_identity_registry_is_loaded(self) -> None:
        import json
        fingerprint = "a" * 64
        env = {
            "JAS_SI_GITHUB_CAPABILITY_WORKLOAD_IDENTITIES": json.dumps({
                fingerprint: {"principal_id": "worker-east-1", "role": "worker"}
            })
        }
        with patch.dict(os.environ, env, clear=True):
            settings = Settings.from_env()
        self.assertIsNotNone(settings.github_capability_workload_identities)
        identity = settings.github_capability_workload_identities._identities[fingerprint]
        self.assertEqual(identity.principal_id, "worker-east-1")
        self.assertEqual(identity.role, "worker")

    def test_invalid_github_capability_workload_identity_config_fails_closed(self) -> None:
        invalid_values = [
            "{not-json",
            "[]",
            '{"' + ("z" * 64) + '":{"principal_id":"worker-east-1","role":"worker"}}',
            '{"' + ("a" * 64) + '":{"principal_id":"worker-east-1","role":"admin"}}',
            '{"' + ("a" * 64) + '":{"principal_id":"worker-east-1"}}',
        ]
        for value in invalid_values:
            with self.subTest(value=value), patch.dict(
                os.environ,
                {"JAS_SI_GITHUB_CAPABILITY_WORKLOAD_IDENTITIES": value},
                clear=True,
            ):
                with self.assertRaises(ValueError):
                    Settings.from_env()

    def test_missing_anchor_credentials_are_allowed(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings.from_env()

        self.assertIsNone(settings.trusted_anchor_hmac_secret)
        self.assertIsNone(settings.trusted_anchor_provider_id)
        self.assertEqual(settings.environment, "development")

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


    def test_vercel_environment_is_used_when_application_override_is_absent(self) -> None:
        with patch.dict(os.environ, {"VERCEL_ENV": "production"}, clear=True):
            settings = Settings.from_env()
        self.assertEqual(settings.environment, "production")

    def test_explicit_application_environment_overrides_vercel(self) -> None:
        with patch.dict(
            os.environ,
            {"JAS_SI_ENVIRONMENT": "test", "VERCEL_ENV": "production"},
            clear=True,
        ):
            settings = Settings.from_env()
        self.assertEqual(settings.environment, "test")

    def test_invalid_vercel_environment_is_rejected(self) -> None:
        with patch.dict(os.environ, {"VERCEL_ENV": "unknown"}, clear=True):
            with self.assertRaisesRegex(ValueError, "Invalid JAS_SI_ENVIRONMENT"):
                Settings.from_env()


    def test_github_oauth_configuration_is_loaded_and_secrets_are_redacted(self) -> None:
        import base64
        import json
        secret = "github-oauth-client-secret-" + "S" * 24
        keyring = json.dumps({"v1": base64.b64encode(b"K" * 32).decode("ascii")})
        env = {
            "JAS_SI_GITHUB_OAUTH_CLIENT_ID": "Iv1." + "a" * 24,
            "JAS_SI_GITHUB_OAUTH_CLIENT_SECRET": secret,
            "JAS_SI_GITHUB_OAUTH_REDIRECT_URI": "https://jas-si.example.test/v1/github/oauth/callback",
            "JAS_SI_GITHUB_OAUTH_ENCRYPTION_KEYRING": keyring,
            "JAS_SI_GITHUB_OAUTH_ACTIVE_KEY_VERSION": "v1",
            "JAS_SI_GITHUB_APP_ID": "4567",
        }
        with patch.dict(os.environ, env, clear=True):
            settings = Settings.from_env()
        self.assertEqual(settings.github_oauth_client_id, env["JAS_SI_GITHUB_OAUTH_CLIENT_ID"])
        self.assertEqual(settings.github_oauth_client_secret, secret)
        self.assertEqual(settings.github_oauth_encryption_keyring, {"v1": b"K" * 32})
        self.assertEqual(settings.github_app_id, 4567)
        self.assertNotIn(secret, repr(settings))
        self.assertNotIn("KKKK", repr(settings))

    def test_partial_github_oauth_configuration_is_rejected(self) -> None:
        with patch.dict(
            os.environ,
            {"JAS_SI_GITHUB_OAUTH_CLIENT_ID": "Iv1." + "a" * 24},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "complete set"):
                Settings.from_env()

    def test_github_oauth_redirect_must_use_exact_callback_path(self) -> None:
        import base64
        import json
        env = {
            "JAS_SI_GITHUB_OAUTH_CLIENT_ID": "Iv1." + "a" * 24,
            "JAS_SI_GITHUB_OAUTH_CLIENT_SECRET": "S" * 32,
            "JAS_SI_GITHUB_OAUTH_REDIRECT_URI": "https://jas-si.example.test/other",
            "JAS_SI_GITHUB_OAUTH_ENCRYPTION_KEYRING": json.dumps(
                {"v1": base64.b64encode(b"K" * 32).decode("ascii")}
            ),
            "JAS_SI_GITHUB_OAUTH_ACTIVE_KEY_VERSION": "v1",
            "JAS_SI_GITHUB_APP_ID": "4567",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(ValueError, "fixed HTTPS JAS-SI callback path"):
                Settings.from_env()

    def test_public_api_settings_ignore_reconciler_private_key(self) -> None:
        with patch.dict(
            os.environ,
            {"JAS_SI_GITHUB_APP_PRIVATE_KEY_B64": "not-base64"},
            clear=True,
        ):
            settings = Settings.from_env()
        self.assertFalse(hasattr(settings, "github_app_private_key_pem"))
        self.assertFalse(hasattr(settings, "github_reconciler_database_url"))

    def test_github_webhook_secret_is_loaded_and_not_exposed(self) -> None:
        secret = "github-webhook-secret-with-at-least-32-bytes"
        with patch.dict(
            os.environ,
            {"JAS_SI_GITHUB_WEBHOOK_SECRET": secret},
            clear=True,
        ):
            settings = Settings.from_env()
        self.assertEqual(settings.github_webhook_secret, secret.encode("utf-8"))
        self.assertNotIn(secret, repr(settings))

    def test_short_github_webhook_secret_is_rejected(self) -> None:
        with patch.dict(
            os.environ,
            {"JAS_SI_GITHUB_WEBHOOK_SECRET": "too-short"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "JAS_SI_GITHUB_WEBHOOK_SECRET"):
                Settings.from_env()

if __name__ == "__main__":
    unittest.main()
