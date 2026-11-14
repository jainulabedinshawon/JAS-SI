import unittest

from fastapi.testclient import TestClient

from jas_si_agent.api import app


class DashboardRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_root_serves_developer_console(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("JAS-SI Reality-Based", response.text)
        self.assertIn("/v1/authorize", response.text)
        self.assertIn("X-API-Key", response.text)

    def test_dashboard_links_openapi_and_docs(self):
        response = self.client.get("/")
        self.assertIn('href="/docs"', response.text)
        self.assertIn('href="/openapi.json"', response.text)
        self.assertIn('href="/health"', response.text)
        self.assertIn('data-lang="curl"', response.text)
        self.assertIn('data-lang="python"', response.text)
        self.assertIn('data-lang="php"', response.text)
        self.assertIn('data-lang="node"', response.text)

    def test_console_points_customers_to_gated_self_service_portal(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn('href="/customer"', response.text)
        self.assertIn("when its dedicated database roles", response.text)
        self.assertIn("technical usage and event history", response.text)
        self.assertIn("These units are not money", response.text)

    def test_health_endpoint_remains_json(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers["content-type"].startswith("application/json")
        )
        self.assertEqual(response.json()["status"], "ok")


if __name__ == "__main__":
    unittest.main()
