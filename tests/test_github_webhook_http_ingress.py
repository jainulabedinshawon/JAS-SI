"""HTTP ingress tests for authenticated, durable GitHub webhooks."""
from __future__ import annotations

import hashlib
import hmac
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from fastapi.testclient import TestClient

from jas_si_agent import api


SECRET = b"test-only-github-webhook-secret-32-bytes"


class FakeInbox:
    def __init__(self, *, inserted=True, status="RECEIVED"):
        self.inserted = inserted
        self.status = status
        self.calls = []

    def receive(self, **kwargs):
        self.calls.append(kwargs)

        class Receipt:
            delivery_id = kwargs["delivery_id"]
            status = self.status
            attempt_count = 0
            inserted = self.inserted

        return Receipt()


class GitHubWebhookHTTPIngressTests(unittest.TestCase):
    def setUp(self):
        self.original_inbox = getattr(api.app.state, "github_webhook_inbox", None)
        self.had_inbox = hasattr(api.app.state, "github_webhook_inbox")
        self.inbox = FakeInbox()
        api.app.state.github_webhook_inbox = self.inbox
        self.settings_patch = patch.object(
            api,
            "settings",
            replace(api.settings, github_webhook_secret=SECRET, github_webhook_database_url=None),
        )
        self.settings_patch.start()
        self.addCleanup(self.settings_patch.stop)
        self.client = TestClient(api.app)

    def tearDown(self):
        if self.had_inbox:
            api.app.state.github_webhook_inbox = self.original_inbox
        elif hasattr(api.app.state, "github_webhook_inbox"):
            delattr(api.app.state, "github_webhook_inbox")

    def _send(self, body=None, *, signature=None, delivery="delivery-001", event="installation"):
        body = body or json.dumps({
            "action": "created",
            "installation": {"id": 183349938, "account": {"login": "untrusted"}},
            "repositories": [{"full_name": "untrusted/repository"}],
            "tenant_id": "untrusted-tenant",
        }, separators=(",", ":")).encode()
        digest = hmac.new(SECRET, body, hashlib.sha256).hexdigest()
        headers = {
            "X-GitHub-Delivery": delivery,
            "X-GitHub-Event": event,
            "X-Hub-Signature-256": signature or "sha256=" + digest,
            "Content-Type": "application/json",
        }
        return self.client.post("/webhooks/github", content=body, headers=headers)

    def test_valid_event_is_durably_received_and_tenant_is_not_inferred(self):
        response = self._send()
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json(), {
            "accepted": True,
            "delivery_id": "delivery-001",
            "duplicate": False,
            "state": "RECEIVED",
        })
        self.assertEqual(len(self.inbox.calls), 1)
        self.assertNotIn("tenant_id", self.inbox.calls[0]["payload"])
        self.assertEqual(len(self.inbox.calls[0]["raw_body_sha256"]), 32)

    def test_duplicate_delivery_is_acknowledged_without_claiming_new_insert(self):
        self.inbox = FakeInbox(inserted=False, status="PROCESSED")
        api.app.state.github_webhook_inbox = self.inbox
        response = self._send()
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.json()["duplicate"])
        self.assertEqual(response.json()["state"], "PROCESSED")

    def test_invalid_signature_never_reaches_persistence(self):
        response = self._send(signature="sha256=" + ("0" * 64))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.inbox.calls, [])

    def test_unsupported_event_never_reaches_persistence(self):
        response = self._send(event="push")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.inbox.calls, [])

    def test_oversized_body_is_rejected_before_persistence(self):
        response = self._send(body=b"x" * 2_000_001)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.inbox.calls, [])

    def test_missing_secret_fails_closed(self):
        with patch.object(api, "settings", replace(api.settings, github_webhook_secret=None)):
            response = self._send()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.inbox.calls, [])


if __name__ == "__main__":
    unittest.main()
