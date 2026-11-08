
"""Startup security tests for the PostgreSQL audit backend."""

from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import patch

from jas_si_agent import api
from jas_si_agent.security_event_store import JsonlSecurityEventStore


class TestAPIStartup(unittest.TestCase):
    def setUp(self):
        self.original_store = api.app.state.security_event_store
        self.jsonl_store = JsonlSecurityEventStore(
            "/tmp/jas-si-startup-test.jsonl"
        )
        api.app.state.security_event_store = self.jsonl_store

    def tearDown(self):
        api.app.state.security_event_store = self.original_store

    def configure(self, **overrides):
        values = {
            "environment": "preview",
            "api_enabled": True,
            "api_key": "test-only-api-key",
            "api_key_pepper": b"test-only-pepper-that-is-at-least-32-bytes",
            "database_url": "postgresql://test:test@localhost/test",
        }
        values.update(overrides)
        return replace(api.settings, **values)

    def test_development_keeps_jsonl_backend(self):
        with (
            patch.object(
                api, "settings",
                self.configure(environment="development"),
            ),
            patch.object(api, "PostgresSecurityEventStore") as postgres,
        ):
            api.initialize_security_event_store()

        postgres.assert_not_called()
        self.assertIs(
            api.app.state.security_event_store,
            self.jsonl_store,
        )

    def test_test_environment_keeps_jsonl_backend(self):
        with (
            patch.object(
                api, "settings",
                self.configure(environment="test"),
            ),
            patch.object(api, "PostgresSecurityEventStore") as postgres,
        ):
            api.initialize_security_event_store()

        postgres.assert_not_called()
        self.assertIs(
            api.app.state.security_event_store,
            self.jsonl_store,
        )

    def test_preview_requires_api_enabled(self):
        with (
            patch.object(
                api, "settings",
                self.configure(api_enabled=False),
            ),
            patch.object(api, "PostgresSecurityEventStore") as postgres,
        ):
            with self.assertRaisesRegex(RuntimeError, "API enabled"):
                api.initialize_security_event_store()

        postgres.assert_not_called()
        self.assertIs(
            api.app.state.security_event_store,
            self.jsonl_store,
        )

    def test_preview_requires_api_key_pepper(self):
        with (
            patch.object(
                api, "settings",
                self.configure(api_key=None, api_key_pepper=None),
            ),
            patch.object(api, "PostgresSecurityEventStore") as postgres,
        ):
            with self.assertRaisesRegex(RuntimeError, "API enabled"):
                api.initialize_security_event_store()

        postgres.assert_not_called()
        self.assertIs(
            api.app.state.security_event_store,
            self.jsonl_store,
        )

    def test_preview_requires_database_url(self):
        with (
            patch.object(
                api, "settings",
                self.configure(database_url=None),
            ),
            patch.object(api, "PostgresSecurityEventStore") as postgres,
        ):
            with self.assertRaisesRegex(RuntimeError, "JAS_SI_DATABASE_URL"):
                api.initialize_security_event_store()

        postgres.assert_not_called()
        self.assertIs(
            api.app.state.security_event_store,
            self.jsonl_store,
        )

    def test_production_also_requires_verified_postgres(self):
        fake_store = unittest.mock.Mock()
        fake_store.verify_integrity.return_value = {
            "valid": True,
            "verified_event_count": 0,
        }

        with (
            patch.object(
                api, "settings",
                self.configure(environment="production"),
            ),
            patch.object(
                api,
                "PostgresSecurityEventStore",
                return_value=fake_store,
            ),
        ):
            api.initialize_security_event_store()

        fake_store.verify_integrity.assert_called_once_with()
        self.assertIs(
            api.app.state.security_event_store,
            fake_store,
        )

    def test_valid_integrity_switches_to_postgres(self):
        fake_store = unittest.mock.Mock()
        fake_store.verify_integrity.return_value = {
            "valid": True,
            "verified_event_count": 3,
            "last_hash": "a" * 64,
        }

        with (
            patch.object(api, "settings", self.configure()),
            patch.object(
                api,
                "PostgresSecurityEventStore",
                return_value=fake_store,
            ) as postgres,
        ):
            api.initialize_security_event_store()

        postgres.assert_called_once_with(
            "postgresql://test:test@localhost/test"
        )
        fake_store.verify_integrity.assert_called_once_with()
        self.assertIs(
            api.app.state.security_event_store,
            fake_store,
        )

    def test_invalid_integrity_denies_startup_without_fallback(self):
        fake_store = unittest.mock.Mock()
        fake_store.verify_integrity.return_value = {
            "valid": False,
            "verified_event_count": 2,
        }

        with (
            patch.object(api, "settings", self.configure()),
            patch.object(
                api,
                "PostgresSecurityEventStore",
                return_value=fake_store,
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "chain is not valid",
            ):
                api.initialize_security_event_store()

        self.assertIs(
            api.app.state.security_event_store,
            self.jsonl_store,
        )

    def test_integrity_exception_denies_startup_without_fallback(self):
        fake_store = unittest.mock.Mock()
        fake_store.verify_integrity.side_effect = RuntimeError(
            "database integrity failure"
        )

        with (
            patch.object(api, "settings", self.configure()),
            patch.object(
                api,
                "PostgresSecurityEventStore",
                return_value=fake_store,
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "integrity verification failed",
            ):
                api.initialize_security_event_store()

        self.assertIs(
            api.app.state.security_event_store,
            self.jsonl_store,
        )


if __name__ == "__main__":
    unittest.main()
