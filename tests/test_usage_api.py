"""Tenant-scoped usage API endpoint tests."""
from datetime import datetime, timezone
from unittest import TestCase
from unittest.mock import patch

from fastapi.testclient import TestClient

from jas_si_agent import api


class FakeUsageMeter:
    def summary(self, *, tenant_id, since):
        return {
            "tenant_id": tenant_id,
            "since": since.isoformat(),
            "units": 3,
            "events": 3,
            "by_operation": [],
            "billing_status": "not_connected",
            "note": "Technical usage only.",
        }


class TestUsageAPI(TestCase):
    def setUp(self):
        self.settings = patch.object(
            api, "settings",
            api.settings.__class__(
                service_name="JAS-SI API", environment="test",
                api_enabled=True, api_key="test-key",
                rate_limit_requests=100, rate_limit_window_seconds=60,
                database_url="postgresql://unused",
            ),
        )
        self.settings.start()
        self.addCleanup(self.settings.stop)
        self.tenant_id = "00000000-0000-0000-0000-000000000011"
        self.key_id = "00000000-0000-0000-0000-000000000022"
        self.previous_meter = getattr(api.app.state, "usage_meter", None)
        api.app.state.usage_meter = FakeUsageMeter()
        self.addCleanup(self._restore_meter)

        def authenticate(request):
            request.state.tenant_id = self.tenant_id
            request.state.api_key_id = self.key_id
            request.state.api_key_scopes = ["usage:read"]

        self.previous_override = api.app.dependency_overrides.get(api._require_api_key)
        api.app.dependency_overrides[api._require_api_key] = authenticate
        self.addCleanup(self._restore_override)
        self.client = TestClient(api.app)

    def _restore_meter(self):
        if self.previous_meter is None:
            if hasattr(api.app.state, "usage_meter"):
                delattr(api.app.state, "usage_meter")
        else:
            api.app.state.usage_meter = self.previous_meter

    def _restore_override(self):
        if self.previous_override is None:
            api.app.dependency_overrides.pop(api._require_api_key, None)
        else:
            api.app.dependency_overrides[api._require_api_key] = self.previous_override

    def test_usage_summary_is_tenant_scoped(self):
        response = self.client.get("/v1/usage")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["tenant_id"], self.tenant_id)
        self.assertEqual(response.json()["units"], 3)
        self.assertEqual(response.json()["billing_status"], "not_connected")

    def test_naive_since_timestamp_is_rejected(self):
        response = self.client.get("/v1/usage?since=2026-11-01T00:00:00")
        self.assertEqual(response.status_code, 422)
