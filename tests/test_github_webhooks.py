"""Adversarial tests for GitHub webhook authentication and parsing."""
import hashlib
import hmac
import json
import unittest

from jas_si_agent.github_webhooks import (
    GitHubWebhookError,
    parse_verified_github_webhook,
    verify_github_webhook_signature,
)


class GitHubWebhookAuthenticationTests(unittest.TestCase):
    secret = b"test-only-webhook-secret"

    def _signature(self, body):
        return "sha256=" + hmac.new(self.secret, body, hashlib.sha256).hexdigest()

    def test_valid_signature_and_installation_event(self):
        body = json.dumps({
            "action": "created",
            "installation": {"id": 183349938, "account": {"login": "example"}},
            "repositories": [{"full_name": "example/repo"}],
        }).encode()
        signature = self._signature(body)
        verify_github_webhook_signature(
            secret=self.secret, raw_body=body, signature_header=signature
        )
        event = parse_verified_github_webhook(
            delivery_id="delivery-001",
            event_name="installation",
            raw_body=body,
        )
        self.assertEqual(event.installation_id, 183349938)
        self.assertEqual(event.action, "created")
        self.assertFalse(hasattr(event, "tenant_id"))

    def test_rejects_modified_body(self):
        body = b'{"action":"created","installation":{"id":1}}'
        with self.assertRaises(GitHubWebhookError):
            verify_github_webhook_signature(
                secret=self.secret,
                raw_body=body + b" ",
                signature_header=self._signature(body),
            )

    def test_rejects_bad_signature_format_and_secret(self):
        for secret, signature in ((b"", self._signature(b"x")), (self.secret, "sha1=bad")):
            with self.subTest(signature=signature):
                with self.assertRaises(GitHubWebhookError):
                    verify_github_webhook_signature(
                        secret=secret, raw_body=b"x", signature_header=signature
                    )

    def test_rejects_unsupported_event_action(self):
        body = b'{"action":"edited","installation":{"id":1}}'
        with self.assertRaises(GitHubWebhookError):
            parse_verified_github_webhook(
                delivery_id="delivery-002",
                event_name="installation",
                raw_body=body,
            )

    def test_accepts_repository_membership_events(self):
        for action in ("added", "removed"):
            body = json.dumps({
                "action": action,
                "installation": {"id": 9},
                "repositories_added": [],
                "repositories_removed": [],
            }).encode()
            event = parse_verified_github_webhook(
                delivery_id=f"delivery-{action}",
                event_name="installation_repositories",
                raw_body=body,
            )
            self.assertEqual(event.action, action)

    def test_rejects_bad_delivery_id_and_installation_id(self):
        for delivery, installation_id in (("../x", 1), ("ok", True), ("ok", 0)):
            body = json.dumps({
                "action": "suspend",
                "installation": {"id": installation_id},
            }).encode()
            with self.subTest(delivery=delivery, installation_id=installation_id):
                with self.assertRaises(GitHubWebhookError):
                    parse_verified_github_webhook(
                        delivery_id=delivery,
                        event_name="installation",
                        raw_body=body,
                    )

    def test_rejects_invalid_json_and_oversized_body(self):
        with self.assertRaises(GitHubWebhookError):
            parse_verified_github_webhook(
                delivery_id="delivery-003",
                event_name="installation",
                raw_body=b"{",
            )
        with self.assertRaises(GitHubWebhookError):
            verify_github_webhook_signature(
                secret=self.secret,
                raw_body=b"x" * 2_000_001,
                signature_header=self._signature(b"x" * 2_000_001),
            )


if __name__ == "__main__":
    unittest.main()
