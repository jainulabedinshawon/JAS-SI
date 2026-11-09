import unittest

from fastapi.testclient import TestClient

from jas_si_agent.api import app


class DemoRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_demo_is_public_html_and_explicitly_synthetic(self):
        response = self.client.get("/demo")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("SIMULATED EXAMPLES", response.text)
        self.assertIn("No GitHub repository", response.text)
        self.assertIn("FALSE_SUCCESS", response.text)
        self.assertIn("INCONCLUSIVE", response.text)

    def test_demo_does_not_request_api_credentials_or_claim_live_verification(self):
        response = self.client.get("/demo")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("X-API-Key", response.text)
        self.assertIn("Real-world verification", response.text)
        self.assertIn("Not performed", response.text)
        self.assertNotIn('fetch("/v1/verify"', response.text)


if __name__ == "__main__":
    unittest.main()
