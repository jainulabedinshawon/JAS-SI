from __future__ import annotations

import unittest
import uuid
from types import SimpleNamespace

from jas_si_agent.github_app_api import GitHubAppAPIError
from jas_si_agent.github_installation_reconciler import (
    ClaimedWebhook,
    PostgresGitHubInstallationReconciler,
)


class FakeGitHub:
    def __init__(self, snapshot=None, error=None):
        self.snapshot_value = snapshot
        self.error = error
        self.calls = []

    def snapshot(self, *, installation_id):
        self.calls.append(installation_id)
        if self.error:
            raise self.error
        return self.snapshot_value


class FakeReconciler(PostgresGitHubInstallationReconciler):
    def __init__(self, github, *, state=("active", "active", 1), processed=True, failed=True):
        self._github = github
        self._events = (
            ClaimedWebhook(
                delivery_id="delivery-1",
                event_name="installation",
                action="created",
                installation_id=98765,
                attempt_count=1,
                claim_token=uuid.uuid4(),
            ),
        )
        self._state = state
        self._processed = processed
        self._failed = failed
        self.processed = []
        self.failed = []
        self.applied = []
        self.pending = ((98765, 1),)

    def claim_pending(self, *, limit=10):
        return self.pending

    def claim(self, *, limit=10, lease_seconds=120):
        return self._events

    def apply_snapshot(self, *, installation_id, snapshot):
        self.applied.append((installation_id, snapshot))
        return self._state

    def mark_processed(self, *, delivery_id, claim_token):
        self.processed.append((delivery_id, claim_token))
        return self._processed

    def mark_failed(self, *, delivery_id, error_code, claim_token, retry_delay_seconds=60):
        self.failed.append((delivery_id, error_code, retry_delay_seconds))
        return self._failed


class GitHubInstallationReconcilerTests(unittest.TestCase):
    def test_webhook_is_only_a_wakeup_and_github_snapshot_is_applied(self):
        snapshot = SimpleNamespace(
            app_id=123456, account_id=7654321,
            account_login="jas-org", account_type="Organization",
            suspended=False, repositories=(),
        )
        github = FakeGitHub(snapshot=snapshot)
        reconciler = FakeReconciler(github)
        result = reconciler.process_batch()
        self.assertEqual(github.calls, [98765])
        self.assertEqual(reconciler.applied, [(98765, snapshot)])
        self.assertEqual(result, {
            "claimed": 1, "processed": 1, "retry": 0, "lease_lost": 0,
        })
        self.assertEqual(len(reconciler.processed), 1)

    def test_missing_pending_claim_is_retried_not_marked_processed(self):
        github = FakeGitHub(snapshot=None)
        reconciler = FakeReconciler(github, state=("NO_CLAIM", "UNCHANGED", 0))
        result = reconciler.process_batch()
        self.assertEqual(result["retry"], 1)
        self.assertEqual(result["processed"], 0)
        self.assertEqual(reconciler.failed[0][1], "CLAIM_NOT_FOUND")
        self.assertEqual(reconciler.processed, [])

    def test_github_api_outage_is_retried_without_logging_provider_details(self):
        github = FakeGitHub(error=GitHubAppAPIError("sensitive provider body must not escape"))
        reconciler = FakeReconciler(github)
        result = reconciler.process_batch()
        self.assertEqual(result["retry"], 1)
        self.assertEqual(reconciler.failed[0][1], "GITHUB_API_UNAVAILABLE")

    def test_pending_claims_are_reconciled_even_without_webhook_delivery(self):
        snapshot = SimpleNamespace(
            app_id=123456, account_id=7654321,
            account_login="jas-org", account_type="Organization",
            suspended=False, repositories=(),
        )
        github = FakeGitHub(snapshot=snapshot)
        reconciler = FakeReconciler(github)
        result = reconciler.process_pending_claims()
        self.assertEqual(github.calls, [98765])
        self.assertEqual(reconciler.applied, [(98765, snapshot)])
        self.assertEqual(result, {"claimed": 1, "reconciled": 1, "retry": 0})

    def test_pending_claim_api_outage_is_left_for_bounded_retry(self):
        github = FakeGitHub(error=GitHubAppAPIError("secret provider response"))
        reconciler = FakeReconciler(github)
        result = reconciler.process_pending_claims()
        self.assertEqual(result, {"claimed": 1, "reconciled": 0, "retry": 1})
        self.assertEqual(reconciler.failed, [])

    def test_terminal_needs_review_claim_is_processed_without_reactivation(self):
        github = FakeGitHub(snapshot=None)
        reconciler = FakeReconciler(
            github, state=("needs_review", "UNCHANGED", 0)
        )
        result = reconciler.process_batch()
        self.assertEqual(result, {
            "claimed": 1, "processed": 1, "retry": 0, "lease_lost": 0,
        })
        self.assertEqual(len(reconciler.processed), 1)
        self.assertEqual(reconciler.failed, [])

    def test_expired_lease_is_not_reported_as_processed(self):
        github = FakeGitHub(snapshot=None)
        reconciler = FakeReconciler(
            github, state=("revoked", "revoked", 0), processed=False
        )
        result = reconciler.process_batch()
        self.assertEqual(result["lease_lost"], 1)
        self.assertEqual(result["processed"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
