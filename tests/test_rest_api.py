
"""Basic tests for the JAS-SI REST API scaffold."""

import unittest
from dataclasses import replace
from unittest.mock import patch

from fastapi.testclient import TestClient

from jas_si_agent import api


class TestJASSIRestAPI(unittest.TestCase):
    def setUp(self):
        # Settings is frozen. Replace the API module's settings reference
        # for this test instead of mutating the original instance.
        self.settings_patcher = patch.object(
            api,
            "settings",
            replace(api.settings, api_enabled=True),
        )
        self.settings_patcher.start()
        self.addCleanup(self.settings_patcher.stop)

        self.client = TestClient(api.app)

    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertTrue(response.json()["api_enabled"])

    def test_authorize_rejects_missing_fields(self):
        response = self.client.post(
            "/v1/authorize",
            json={},
        )

        self.assertEqual(response.status_code, 422)

    def test_verify_rejects_missing_fields(self):
        response = self.client.post(
            "/v1/verify",
            json={},
        )

        self.assertEqual(response.status_code, 422)

    def test_verify_rejects_incomplete_evidence(self):
        response = self.client.post(
            "/v1/verify",
            json={
                "action_id": "test-action-1",
                "claimed_success": True,
                "observed_state": "completed",
                "collected_independently": True,
            },
        )

        # Evidence reference is required when evidence is submitted.
        self.assertEqual(response.status_code, 422)

    def test_disabled_api_returns_503(self):
        # Confirm that the API's disabled state is still enforced.
        with patch.object(
            api,
            "settings",
            replace(api.settings, api_enabled=False),
        ):
            response = self.client.post(
                "/v1/verify",
                json={
                    "action_id": "test-action-2",
                    "claimed_success": True,
                    "observed_state": "completed",
                    "evidence_ref": "ci://test/evidence-2",
                    "collected_independently": True,
                },
            )

        self.assertEqual(response.status_code, 503)

    def test_health_reports_api_enabled_state(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertIs(response.json()["api_enabled"], True)


if __name__ == "__main__":
    unittest.main()
