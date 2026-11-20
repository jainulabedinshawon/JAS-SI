"""The GitHub App reconciler must not execute inside the public API process."""
from __future__ import annotations

import importlib
import unittest

from fastapi.testclient import TestClient

api = importlib.import_module("jas_si_agent.api")


class GitHubReconcilerApiIsolationTests(unittest.TestCase):
    def test_public_api_does_not_expose_reconciler_trigger(self):
        client = TestClient(api.app, base_url="https://jas-si.example.test")
        try:
            response = client.post(
                "/internal/github/reconcile",
                headers={"Authorization": "Bearer " + "x" * 48},
            )
        finally:
            client.close()
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
