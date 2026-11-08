from __future__ import annotations

import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from fastapi.testclient import TestClient
from jas_si_agent import api
from jas_si_agent.api_key_registry import AuthenticatedApiKey
from jas_si_agent.security_event_store import JsonlSecurityEventStore


class TestTenantApiKeyAuthentication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.original_store = api.app.state.security_event_store
        api.app.state.security_event_store = JsonlSecurityEventStore(
            Path(self.temp.name) / "audit.jsonl"
        )
        self.addCleanup(
            setattr, api.app.state, "security_event_store", self.original_store
        )
        self.settings = replace(
            api.settings,
            environment="production",
            api_enabled=True,
            api_key=None,
            api_key_pepper=b"test-pepper-with-at-least-32-bytes-long",
            database_url="postgresql://test:test@localhost/test",
        )
        self.settings_patch = patch.object(api, "settings", self.settings)
        self.settings_patch.start()
        self.addCleanup(self.settings_patch.stop)
        self.startup_patch = patch.object(api.app.router, "on_startup", [])
        self.startup_patch.start()
        self.addCleanup(self.startup_patch.stop)
        with api._rate_limit_lock:
            api._rate_limit_buckets.clear()
        self.client = TestClient(api.app)
        self.tenant_id = uuid4()
        self.key_id = uuid4()
        self.token = "jassi_live_test-token-value"

    def _auth_result(self, scopes):
        return AuthenticatedApiKey(
            key_id=self.key_id,
            tenant_id=self.tenant_id,
            tenant_name="Pilot Tenant",
            scopes=frozenset(scopes),
        )

    def test_unknown_key_returns_generic_401(self):
        with patch.object(api, "PostgresApiKeyRegistry") as registry:
            registry.return_value.authenticate.return_value = None
            response = self.client.post(
                "/v1/verify",
                headers={"X-API-Key": self.token},
                json={"action_id": "pilot-1", "claimed_success": True},
            )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Missing or invalid API key")

    def test_missing_key_returns_401_without_database_lookup(self):
        with patch.object(api, "PostgresApiKeyRegistry") as registry:
            response = self.client.post(
                "/v1/verify",
                json={"action_id": "pilot-1", "claimed_success": True},
            )
        self.assertEqual(response.status_code, 401)
        registry.assert_not_called()

    def test_scope_mismatch_returns_403(self):
        with patch.object(api, "PostgresApiKeyRegistry") as registry:
            registry.return_value.authenticate.return_value = self._auth_result(
                ["authorization:check"]
            )
            response = self.client.post(
                "/v1/verify",
                headers={"X-API-Key": self.token},
                json={"action_id": "pilot-1", "claimed_success": True},
            )
        self.assertEqual(response.status_code, 403)

    def test_valid_scoped_key_reaches_outcome_endpoint(self):
        with patch.object(api, "PostgresApiKeyRegistry") as registry:
            registry.return_value.authenticate.return_value = self._auth_result(
                ["outcomes:submit"]
            )
            response = self.client.post(
                "/v1/verify",
                headers={"X-API-Key": self.token},
                json={"action_id": "pilot-1", "claimed_success": True},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["evidence_origin"], "not_provided")

    def test_registry_outage_fails_closed_with_503(self):
        with patch.object(api, "PostgresApiKeyRegistry") as registry:
            registry.return_value.authenticate.side_effect = RuntimeError("db down")
            response = self.client.post(
                "/v1/verify",
                headers={"X-API-Key": self.token},
                json={"action_id": "pilot-1", "claimed_success": True},
            )
        self.assertEqual(response.status_code, 503)

    def test_deployed_auth_never_falls_back_to_legacy_static_key(self):
        self.settings_patch.stop()
        self.settings_patch = patch.object(
            api,
            "settings",
            replace(self.settings, api_key=self.token),
        )
        self.settings_patch.start()
        with patch.object(api, "PostgresApiKeyRegistry") as registry:
            registry.return_value.authenticate.return_value = None
            response = self.client.post(
                "/v1/verify",
                headers={"X-API-Key": self.token},
                json={"action_id": "pilot-1", "claimed_success": True},
            )
        self.assertEqual(response.status_code, 401)
        registry.return_value.authenticate.assert_called_once_with(self.token)


if __name__ == "__main__":
    unittest.main()
