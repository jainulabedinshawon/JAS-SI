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


class FakeQuotaMeter:
    def events_authenticated(self, **query):
        return {"items": [], "next_cursor": None}

    def record_authenticated(self, **event):
        return {
            "event_id": "00000000-0000-0000-0000-000000000099",
            "operation": event["operation"],
            "units": 1,
            "replayed": False,
            "monthly_limit": event["monthly_limit"],
            "used_units": 1,
            "remaining_units": event["monthly_limit"] - 1,
            "resets_at": "2026-12-01T00:00:00+00:00",
        }



class FakeSharedApiRateLimiter:
    def check(self, client_ip, *, limit, window_seconds):
        return True, max(0, limit - 1), 0


class TestTenantApiKeyAuthentication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.original_store = api.app.state.security_event_store
        self.original_meter = getattr(api.app.state, "usage_meter", None)
        self.original_api_limiter = getattr(api.app.state, "api_rate_limiter", None)
        api.app.state.usage_meter = FakeQuotaMeter()
        api.app.state.api_rate_limiter = FakeSharedApiRateLimiter()
        self.addCleanup(self._restore_meter)
        self.addCleanup(self._restore_api_limiter)
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
        self.client = TestClient(
            api.app,
            headers={"X-Vercel-Forwarded-For": "203.0.113.90"},
        )
        self.tenant_id = uuid4()
        self.key_id = uuid4()
        self.token = "jassi_live_test-token-value"

    def _restore_api_limiter(self):
        if self.original_api_limiter is None:
            if hasattr(api.app.state, "api_rate_limiter"):
                delattr(api.app.state, "api_rate_limiter")
        else:
            api.app.state.api_rate_limiter = self.original_api_limiter

    def _restore_meter(self):
        if self.original_meter is None:
            if hasattr(api.app.state, "usage_meter"):
                delattr(api.app.state, "usage_meter")
        else:
            api.app.state.usage_meter = self.original_meter

    def _auth_result(self, scopes):
        return AuthenticatedApiKey(
            key_id=self.key_id,
            tenant_id=self.tenant_id,
            tenant_name="Pilot Tenant",
            scopes=frozenset(scopes),
            candidate_digest=b"c" * 32,
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

    def test_usage_history_requires_usage_read_scope(self):
        with patch.object(api, "PostgresApiKeyRegistry") as registry:
            registry.return_value.authenticate.return_value = self._auth_result(
                ["authorization:check"]
            )
            response = self.client.get(
                "/v1/usage/events",
                headers={"X-API-Key": self.token},
            )
        self.assertEqual(response.status_code, 403)

    def test_usage_history_accepts_usage_read_scope(self):
        with patch.object(api, "PostgresApiKeyRegistry") as registry:
            registry.return_value.authenticate.return_value = self._auth_result(
                ["usage:read"]
            )
            response = self.client.get(
                "/v1/usage/events?limit=20",
                headers={"X-API-Key": self.token},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"items": [], "next_cursor": None})

    def test_valid_scoped_key_keeps_candidate_digest_request_local(self):
        with (
            patch.object(api, "PostgresApiKeyRegistry") as registry,
            patch.object(api, "_record_usage_for_authenticated_tenant", wraps=api._record_usage_for_authenticated_tenant) as record_usage,
        ):
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
        request = record_usage.call_args.args[0]
        self.assertEqual(request.state.api_key_candidate_digest, b"c" * 32)
        self.assertNotIn("candidate_digest", response.text)
        self.assertNotIn((b"c" * 32).hex(), response.text)

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
