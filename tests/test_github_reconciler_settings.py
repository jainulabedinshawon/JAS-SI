"""Environment isolation tests for the dedicated GitHub App reconciler."""
from __future__ import annotations

import base64
import os
import unittest
from unittest.mock import patch

from jas_si_agent.github_installation_reconciler import GitHubReconcilerSettings


class GitHubReconcilerSettingsTests(unittest.TestCase):
    def test_loads_only_worker_credentials_and_redacts_them(self):
        private_key = b"-----BEGIN PRIVATE KEY-----\\nnot-a-real-key\\n-----END PRIVATE KEY-----\\n"
        env = {
            "JAS_SI_GITHUB_APP_ID": "12345",
            "JAS_SI_GITHUB_APP_PRIVATE_KEY_B64": base64.b64encode(private_key).decode("ascii"),
            "JAS_SI_GITHUB_RECONCILER_DATABASE_URL": "postgresql://reconciler:secret@db.example.test/jas_si",
            "JAS_SI_GITHUB_RECONCILER_POLL_SECONDS": "30",
        }
        with patch.dict(os.environ, env, clear=True):
            settings = GitHubReconcilerSettings.from_env()
        self.assertEqual(settings.app_id, 12345)
        self.assertEqual(settings.private_key_pem, private_key)
        self.assertEqual(settings.poll_seconds, 30)
        self.assertNotIn("not-a-real-key", repr(settings))
        self.assertNotIn("secret", repr(settings))

    def test_rejects_missing_private_key_or_database_dsn(self):
        with patch.dict(os.environ, {"JAS_SI_GITHUB_APP_ID": "12345"}, clear=True):
            with self.assertRaisesRegex(ValueError, "private key"):
                GitHubReconcilerSettings.from_env()

    def test_rejects_out_of_range_poll_interval(self):
        private_key = b"-----BEGIN PRIVATE KEY-----\\nplaceholder\\n-----END PRIVATE KEY-----\\n"
        env = {
            "JAS_SI_GITHUB_APP_ID": "12345",
            "JAS_SI_GITHUB_APP_PRIVATE_KEY_B64": base64.b64encode(private_key).decode("ascii"),
            "JAS_SI_GITHUB_RECONCILER_DATABASE_URL": "postgresql://db.example.test/jas_si",
            "JAS_SI_GITHUB_RECONCILER_POLL_SECONDS": "301",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(ValueError, "POLL_SECONDS"):
                GitHubReconcilerSettings.from_env()


if __name__ == "__main__":
    unittest.main(verbosity=2)
