"""Tests for JAS-SI REST API authentication, OpenAPI, and rate limiting."""

from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import patch

from fastapi.testclient import TestClient

from jas_si_agent import api

TEST_API_KEY = "test-only-jas-si-api-key"


class TestJASSIRestAPI(unittest.TestCase):
    def setUp(self):
        self.settings_patcher = patch.object(
            api,
            "settings",
            replace(
                api.settings,
                api_enabled=True,
                api_key=TEST_API_KEY,
                rate_limit_requests=60,
                rate_limit_window_seconds=60,
            ),
        )
        self.settings_patcher.start()
        self.addCleanup(self.settings_patcher.stop)

        with api._rate_limit_lock:
            api._rate_limit_buckets.clear()
        self.client = TestClient(api.app)
        self.valid_headers = {"X-API-Key": TEST_API_KEY}

    def test_health_endpoint_is_public(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertTrue(response.json()["api_enabled"])
        self.assertNotIn("api_key", response.json())
        self.assertNotIn(TEST_API_KEY, response.text)

    def test_security_headers_are_present(self):
        response = self.client.get("/health")
        expected_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": (
                "camera=(), microphone=(), geolocation=()"
            ),
        }
        for name, expected in expected_headers.items():
            with self.subTest(header=name):
                self.assertEqual(
                    response.headers.get(name),
                    expected,
                )

    def test_openapi_documents_api_key_scheme(self):
        response = self.client.get("/openapi.json")
        self.assertEqual(response.status_code, 200)
        schemes = response.json()["components"]["securitySchemes"]
        self.assertIn("ApiKeyAuth", schemes)
        self.assertEqual(schemes["ApiKeyAuth"]["type"], "apiKey")
        self.assertEqual(schemes["ApiKeyAuth"]["in"], "header")
        self.assertEqual(schemes["ApiKeyAuth"]["name"], "X-API-Key")

    def test_protected_endpoints_document_api_key_security(self):
        schema = self.client.get("/openapi.json").json()
        for path in ("/v1/authorize", "/v1/verify"):
            with self.subTest(path=path):
                operation = schema["paths"][path]["post"]
                self.assertTrue(
                    any(
                        "ApiKeyAuth" in requirement
                        for requirement in operation.get("security", [])
                    )
                )

    def test_health_endpoint_is_not_documented_as_protected(self):
        schema = self.client.get("/openapi.json").json()
        operation = schema["paths"]["/health"]["get"]
        self.assertNotIn("security", operation)

    def test_swagger_and_redoc_are_available(self):
        self.assertEqual(self.client.get("/docs").status_code, 200)
        self.assertEqual(self.client.get("/redoc").status_code, 200)

    def test_authorize_rejects_missing_fields(self):
        response = self.client.post(
            "/v1/authorize",
            json={},
            headers=self.valid_headers,
        )
        self.assertEqual(response.status_code, 422)

    def test_verify_rejects_missing_fields(self):
        response = self.client.post(
            "/v1/verify",
            json={},
            headers=self.valid_headers,
        )
        self.assertEqual(response.status_code, 422)

    def test_verify_rejects_incomplete_evidence(self):
        response = self.client.post(
            "/v1/verify",
            headers=self.valid_headers,
            json={
                "action_id": "test-action-1",
                "claimed_success": True,
                "observed_state": "completed",
                "collected_independently": True,
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_missing_api_key_returns_401(self):
        response = self.client.post(
            "/v1/verify",
            json={
                "action_id": "test-action-2",
                "claimed_success": True,
            },
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.headers.get("WWW-Authenticate"),
            "ApiKey",
        )

    def test_invalid_api_key_returns_401(self):
        response = self.client.post(
            "/v1/verify",
            headers={"X-API-Key": "incorrect-test-key"},
            json={
                "action_id": "test-action-3",
                "claimed_success": True,
            },
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.headers.get("WWW-Authenticate"),
            "ApiKey",
        )

    def test_unconfigured_api_key_fails_closed(self):
        with patch.object(
            api,
            "settings",
            replace(api.settings, api_key=None),
        ):
            response = self.client.post(
                "/v1/verify",
                headers=self.valid_headers,
                json={
                    "action_id": "test-action-4",
                    "claimed_success": True,
                },
            )
            self.assertEqual(response.status_code, 503)

    def test_disabled_api_returns_503(self):
        with patch.object(
            api,
            "settings",
            replace(api.settings, api_enabled=False),
        ):
            response = self.client.post(
                "/v1/verify",
                headers=self.valid_headers,
                json={
                    "action_id": "test-action-5",
                    "claimed_success": True,
                },
            )
            self.assertEqual(response.status_code, 503)

    def test_verify_validates_evidence_with_valid_api_key(self):
        response = self.client.post(
            "/v1/verify",
            headers=self.valid_headers,
            json={
                "action_id": "test-action-6",
                "claimed_success": True,
                "observed_state": "completed",
                "collected_independently": True,
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_rate_limit_returns_429_after_configured_limit(self):
        with patch.object(
            api,
            "settings",
            replace(
                api.settings,
                rate_limit_requests=2,
                rate_limit_window_seconds=60,
            ),
        ):
            first = self.client.post(
                "/v1/verify",
                headers=self.valid_headers,
                json={},
            )
            second = self.client.post(
                "/v1/verify",
                headers=self.valid_headers,
                json={},
            )
            third = self.client.post(
                "/v1/verify",
                headers=self.valid_headers,
                json={},
            )
            # The first two reach request validation; the third is throttled.
            self.assertEqual(first.status_code, 422)
            self.assertEqual(second.status_code, 422)
            self.assertEqual(third.status_code, 429)
            self.assertEqual(
                third.headers.get("X-RateLimit-Limit"),
                "2",
            )
            self.assertEqual(
                third.headers.get("X-RateLimit-Remaining"),
                "0",
            )
            self.assertIn("Retry-After", third.headers)
            self.assertEqual(
                third.headers.get("X-Content-Type-Options"),
                "nosniff",
            )

    def test_health_endpoint_is_not_rate_limited(self):
        with patch.object(
            api,
            "settings",
            replace(
                api.settings,
                rate_limit_requests=1,
                rate_limit_window_seconds=60,
            ),
        ):
            first = self.client.get("/health")
            second = self.client.get("/health")
            self.assertEqual(first.status_code, 200)
            self.assertEqual(second.status_code, 200)

    def test_rate_limit_configuration_must_be_positive(self):
        from jas_si_agent.config import _read_positive_int

        with patch.dict(
            "os.environ",
            {"JAS_SI_TEST_LIMIT": "0"},
        ):
            with self.assertRaises(ValueError):
                _read_positive_int("JAS_SI_TEST_LIMIT", 60)


if __name__ == "__main__":
    unittest.main()
