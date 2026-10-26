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

    def test_response_includes_server_generated_request_id(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        request_id = response.headers.get("X-Request-ID")
        self.assertIsNotNone(request_id)
        self.assertRegex(request_id, r"^[0-9a-f]{32}$")

    def test_authentication_failure_is_logged_without_api_key(self):
        with patch.object(api.logger, "info") as mock_info:
            response = self.client.post(
                "/v1/verify",
                headers={"X-API-Key": "incorrect-test-key"},
                json={
                    "action_id": "test-action-log",
                    "claimed_success": True,
                },
            )

        self.assertEqual(response.status_code, 401)
        self.assertTrue(mock_info.called)

        log_line = mock_info.call_args.args[0]
        import json

        event = json.loads(log_line)
        self.assertEqual(event["event_type"], "authentication_failure")
        self.assertEqual(event["reason_code"], "invalid_api_key")
        self.assertEqual(event["status_code"], 401)
        self.assertIn("request_id", event)
        self.assertNotIn(TEST_API_KEY, log_line)
        self.assertNotIn("incorrect-test-key", log_line)

    def test_rate_limit_exceeded_is_logged(self):
        with patch.object(
            api,
            "settings",
            replace(
                api.settings,
                rate_limit_requests=1,
                rate_limit_window_seconds=60,
            ),
        ):
            with patch.object(api.logger, "info") as mock_info:
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

        self.assertEqual(first.status_code, 422)
        self.assertEqual(second.status_code, 429)

        events = [
            __import__("json").loads(call.args[0])
            for call in mock_info.call_args_list
        ]
        rate_limit_events = [
            event
            for event in events
            if event["event_type"] == "rate_limit_exceeded"
        ]
        self.assertEqual(len(rate_limit_events), 1)
        self.assertEqual(rate_limit_events[0]["status_code"], 429)
        self.assertIn("request_id", rate_limit_events[0])

    def test_security_log_reserved_fields_cannot_be_overridden(self):
        import json

        with patch.object(api.logger, "info") as mock_info:
            api._log_security_event(
                "schema_integrity_test",
                timestamp="forged-timestamp",
                status_code=200,
            )

        self.assertTrue(mock_info.called)
        event = json.loads(mock_info.call_args.args[0])
        self.assertEqual(event["event_type"], "schema_integrity_test")
        self.assertNotEqual(event["timestamp"], "forged-timestamp")
        self.assertEqual(event["status_code"], 200)

    def test_logging_failure_does_not_bypass_authentication(self):
        with patch.object(
            api.logger,
            "info",
            side_effect=RuntimeError("simulated logger failure"),
        ):
            response = self.client.post(
                "/v1/verify",
                json={
                    "action_id": "logging-failure-test",
                    "claimed_success": True,
                },
            )

        # Logging must fail safely; authentication must still reject the call.
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.headers.get("WWW-Authenticate"),
            "ApiKey",
        )

    def test_logging_failure_does_not_break_public_health(self):
        with patch.object(
            api.logger,
            "info",
            side_effect=RuntimeError("simulated logger failure"),
        ):
            response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertTrue(response.headers.get("X-Request-ID"))


if __name__ == "__main__":
    unittest.main()
