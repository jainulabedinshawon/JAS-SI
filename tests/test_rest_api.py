"""Tests for the JAS-SI REST API security and OpenAPI contract."""

import unittest
from dataclasses import replace
from unittest.mock import patch

from fastapi.testclient import TestClient

from jas_si_agent import api

TEST_API_KEY = "test-only-jas-si-api-key"


class TestJASSIRestAPI(unittest.TestCase):
    def setUp(self):
        # Settings is frozen; replace the reference for each test.
        self.settings_patcher = patch.object(
            api,
            "settings",
            replace(
                api.settings,
                api_enabled=True,
                api_key=TEST_API_KEY,
            ),
        )
        self.settings_patcher.start()
        self.addCleanup(self.settings_patcher.stop)

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
        self.assertEqual(
            response.headers.get("X-Content-Type-Options"),
            "nosniff",
        )
        self.assertEqual(
            response.headers.get("X-Frame-Options"),
            "DENY",
        )
        self.assertEqual(
            response.headers.get("Referrer-Policy"),
            "no-referrer",
        )
        self.assertEqual(
            response.headers.get("Permissions-Policy"),
            "camera=(), microphone=(), geolocation=()",
        )

    def test_openapi_documents_api_key_scheme(self):
        response = self.client.get("/openapi.json")
        self.assertEqual(response.status_code, 200)
        schema = response.json()
        schemes = schema["components"]["securitySchemes"]
        self.assertIn("ApiKeyAuth", schemes)
        self.assertEqual(
            schemes["ApiKeyAuth"]["type"],
            "apiKey",
        )
        self.assertEqual(
            schemes["ApiKeyAuth"]["in"],
            "header",
        )
        self.assertEqual(
            schemes["ApiKeyAuth"]["name"],
            "X-API-Key",
        )

    def test_protected_endpoints_document_api_key_security(self):
        response = self.client.get("/openapi.json")
        self.assertEqual(response.status_code, 200)
        schema = response.json()
        paths = schema["paths"]
        for path in ("/v1/authorize", "/v1/verify"):
            with self.subTest(path=path):
                operation = paths[path]["post"]
                self.assertIn("security", operation)
                self.assertTrue(
                    any(
                        "ApiKeyAuth" in requirement
                        for requirement in operation["security"]
                    )
                )

    def test_health_endpoint_is_not_documented_as_protected(self):
        response = self.client.get("/openapi.json")
        self.assertEqual(response.status_code, 200)
        operation = response.json()["paths"]["/health"]["get"]
        self.assertNotIn("security", operation)

    def test_swagger_and_redoc_are_available(self):
        docs_response = self.client.get("/docs")
        redoc_response = self.client.get("/redoc")
        self.assertEqual(docs_response.status_code, 200)
        self.assertEqual(redoc_response.status_code, 200)

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
        # Authentication succeeds; evidence_ref is still missing.
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
