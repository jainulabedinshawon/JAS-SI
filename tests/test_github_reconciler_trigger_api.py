"""Authenticated scheduler boundary tests for GitHub reconciliation."""
from __future__ import annotations

import importlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

api = importlib.import_module("jas_si_agent.api")


class _FakeReconciler:
    def __init__(self):
        self.webhook_calls = []
        self.pending_calls = []
        self.webhook_claimed = 1

    def process_batch(self, *, limit):
        self.webhook_calls.append(limit)
        return {
            "claimed": self.webhook_claimed,
            "processed": self.webhook_claimed,
            "retry": 0,
            "lease_lost": 0,
        }

    def process_pending_claims(self, *, limit):
        self.pending_calls.append(limit)
        return {"claimed": 1, "reconciled": 1, "retry": 0}


class GitHubReconcilerTriggerApiTests(unittest.TestCase):
    def setUp(self):
        self.old_settings = api.settings
        self.secret = b"scheduler-trigger-secret-material-32-bytes"
        api.settings = SimpleNamespace(github_reconciler_trigger_secret=self.secret)
        self.client = TestClient(api.app, base_url="https://jas-si.example.test")
        self.reconciler = _FakeReconciler()
        self.factory = patch.object(api, "build_reconciler", return_value=self.reconciler)
        self.mock_factory = self.factory.start()

    def tearDown(self):
        self.factory.stop()
        self.client.close()
        api.settings = self.old_settings

    def test_rejects_missing_or_invalid_bearer_token(self):
        missing = self.client.post("/internal/github/reconcile")
        invalid = self.client.post(
            "/internal/github/reconcile",
            headers={"Authorization": "Bearer " + "x" * 40},
        )
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(invalid.status_code, 401)
        self.mock_factory.assert_not_called()

    def test_runs_only_bounded_batches_after_valid_bearer_authentication(self):
        response = self.client.post(
            "/internal/github/reconcile",
            headers={"Authorization": "Bearer " + self.secret.decode()},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(self.reconciler.webhook_calls, [1])
        self.assertEqual(self.reconciler.pending_calls, [])
        self.assertEqual(response.json()["webhook"]["processed"], 1)
        self.assertEqual(response.json()["pending_claims"]["claimed"], 0)

    def test_polls_one_pending_claim_only_when_webhook_queue_is_empty(self):
        self.reconciler.webhook_claimed = 0
        response = self.client.post(
            "/internal/github/reconcile",
            headers={"Authorization": "Bearer " + self.secret.decode()},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.reconciler.webhook_calls, [1])
        self.assertEqual(self.reconciler.pending_calls, [1])
        self.assertEqual(response.json()["pending_claims"]["reconciled"], 1)

    def test_fails_closed_when_scheduler_secret_is_not_configured(self):
        api.settings = SimpleNamespace(github_reconciler_trigger_secret=None)
        response = self.client.post(
            "/internal/github/reconcile",
            headers={"Authorization": "Bearer " + self.secret.decode()},
        )
        self.assertEqual(response.status_code, 503)
        self.mock_factory.assert_not_called()

    def test_hides_reconciler_failures_from_public_response(self):
        self.mock_factory.side_effect = RuntimeError("private DSN must not leak")
        response = self.client.post(
            "/internal/github/reconcile",
            headers={"Authorization": "Bearer " + self.secret.decode()},
        )
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private DSN", response.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
