import unittest

from fastapi.testclient import TestClient

from jas_si_agent.api import app


class LiveGitHubDemoRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_live_github_demo_is_served(self):
        response = self.client.get("/live-demo")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("Live GitHub evidence check", response.text)

    def test_live_demo_calls_real_evidence_endpoint_without_persisting_key(self):
        response = self.client.get("/live-demo")
        self.assertEqual(response.status_code, 200)
        self.assertIn('fetch("/v1/github/evidence"', response.text)
        self.assertIn('"X-API-Key": apiKey', response.text)
        self.assertIn("keyField.value = \"\"", response.text)
        self.assertNotIn("localStorage", response.text)
        self.assertNotIn("sessionStorage", response.text)
        self.assertIn("semantic_truth_verified", response.text)
        self.assertIn("read-only", response.text.lower())


if __name__ == "__main__":
    unittest.main()
