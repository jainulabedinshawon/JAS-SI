"""Basic tests for the JAS-SI REST API scaffold."""

import unittest

from fastapi.testclient import TestClient

from jas_si_agent.api import app

client = TestClient(app)


class TestJASSIRestAPI(unittest.TestCase):
    def test_health_endpoint(self):
        response = client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertIn("api_enabled", response.json())

    def test_authorize_rejects_missing_fields(self):
        response = client.post("/v1/authorize", json={})

        self.assertEqual(response.status_code, 422)

    def test_verify_rejects_missing_fields(self):
        response = client.post("/v1/verify", json={})

        self.assertEqual(response.status_code, 422)

    def test_verify_rejects_incomplete_evidence(self):
        response = client.post(
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


if __name__ == "__main__":
    unittest.main()
