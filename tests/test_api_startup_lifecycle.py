
"""Integration tests for the FastAPI startup security lifecycle."""

from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from jas_si_agent import api


class TestAPIStartupLifecycle(unittest.TestCase):
    def setUp(self):
        self.original_store = api.app.state.security_event_store
        self.rate_limiter_patcher = patch.object(api, "PostgresApiRateLimiter")
        self.rate_limiter_patcher.start()

    def tearDown(self):
        self.rate_limiter_patcher.stop()
        api.app.state.security_event_store = self.original_store

    def configure(self, **overrides):
        values = {
            "environment": "preview",
            "api_enabled": True,
            "api_key": "lifecycle-test-key",
            "api_key_pepper": b"lifecycle-test-pepper-at-least-32-bytes",
            "database_url": "postgresql://test:test@localhost/test",
            "api_rate_limit_pepper": b"api-rate-limit-test-pepper-at-least-32-bytes",
        }
        values.update(overrides)
        return replace(api.settings, **values)

    def test_preview_startup_runs_integrity_check(self):
        fake_store = Mock()
        fake_store.verify_integrity.return_value = {
            "valid": True,
            "verified_event_count": 0,
            "last_hash": "0" * 64,
        }

        with (
            patch.object(api, "settings", self.configure()),
            patch.object(
                api,
                "PostgresSecurityEventStore",
                return_value=fake_store,
            ),
            patch.object(api, "PostgresApiKeyRegistry") as registry,
            patch.object(api, "PostgresUsageMeter") as usage_meter,
        ):
            registry.return_value.verify_schema.return_value = True
            registry.return_value.verify_api_key_auth_boundary.return_value = True
            usage_meter.return_value.verify_api_key_usage_routines.return_value = True
            with TestClient(api.app) as client:
                response = client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        fake_store.verify_integrity.assert_called_once_with()
        registry.return_value.verify_schema.assert_called_once_with()
        registry.return_value.verify_api_key_auth_boundary.assert_called_once_with()
        usage_meter.return_value.verify_api_key_usage_routines.assert_called_once_with()
        self.assertIs(api.app.state.security_event_store, fake_store)

    def test_preview_startup_rejects_missing_database_url(self):
        with (
            patch.object(
                api,
                "settings",
                self.configure(database_url=None),
            ),
            patch.object(api, "PostgresSecurityEventStore") as postgres,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "JAS_SI_DATABASE_URL",
            ):
                with TestClient(api.app):
                    pass

        postgres.assert_not_called()

    def test_preview_startup_rejects_invalid_integrity(self):
        fake_store = Mock()
        fake_store.verify_integrity.return_value = {
            "valid": False,
            "verified_event_count": 1,
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
                with TestClient(api.app):
                    pass

        self.assertIs(
            api.app.state.security_event_store,
            self.original_store,
        )

    def test_preview_startup_rejects_integrity_exception(self):
        fake_store = Mock()
        fake_store.verify_integrity.side_effect = RuntimeError(
            "simulated database failure"
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
                with TestClient(api.app):
                    pass

        self.assertIs(
            api.app.state.security_event_store,
            self.original_store,
        )


if __name__ == "__main__":
    unittest.main()
