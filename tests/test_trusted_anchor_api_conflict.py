from __future__ import annotations

import sys
import unittest
from dataclasses import asdict
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_api_client import (
    TrustedAnchorApiClient,
    TrustedAnchorApiClientError,
    TrustedAnchorApiIdempotencyConflict,
    TrustedAnchorApiRequestInProgress,
)
from jas_si_agent.trusted_anchor_api_contract import (
    TrustedAnchorApiContract,
)
from jas_si_agent.trusted_anchor_hmac import (
    create_signed_receipt,
)
from jas_si_agent.trusted_anchor_http_transport import (
    TrustedAnchorHttpTransport,
)
from jas_si_agent.trusted_anchor_provider_profile import (
    TrustedAnchorProviderProfile,
)


TOKEN = "test-api-token-value-123456789"
SECRET = b"jas-si-api-conflict-secret-minimum-32-bytes"


class TestTrustedAnchorApiConflictRejection(unittest.TestCase):

    def setUp(self):
        self.profile = TrustedAnchorProviderProfile(
            provider_id="example-provider",
            base_url="https://anchors.example.com",
        )

        self.anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=50,
            last_hash="a" * 64,
        )

        self.other_anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=51,
            last_hash="b" * 64,
        )

        self.contract = TrustedAnchorApiContract(
            publish_path="v1/anchors",
            lookup_path_template=(
                "v1/anchors/by-key/{idempotency_key}"
            ),
            idempotency_header="Idempotency-Key",
            success_status_codes=(200, 201),
            lookup_not_found_status_code=404,
        )

        self.requests = []

    def make_client(self, handler):
        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        )

        transport = TrustedAnchorHttpTransport(
            self.profile,
            client=http_client,
        )

        client = TrustedAnchorApiClient(
            self.profile,
            transport,
            bearer_token=TOKEN,
            contract=self.contract,
        )

        self.addCleanup(http_client.close)
        return client

    def test_existing_key_reused_for_different_anchor_is_rejected(self):
        def handler(request):
            self.requests.append(request)
            return httpx.Response(500)

        client = self.make_client(handler)

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(
                self.other_anchor,
                idempotency_key=self.anchor.digest,
            )

        self.assertEqual(
            len(self.requests),
            0,
            "Conflicting key reuse must be rejected before network access",
        )

    def test_provider_receipt_with_different_payload_digest_is_rejected(self):
        mismatched_receipt = create_signed_receipt(
            provider_id="example-provider",
            anchor_digest=self.other_anchor.digest,
            external_reference="mismatched-anchor-reference",
            observed_at="2026-11-01T12:00:00Z",
            secret=SECRET,
        )

        def handler(request):
            self.requests.append(request)

            return httpx.Response(
                201,
                headers={
                    "Content-Type": "application/json",
                },
                json=asdict(mismatched_receipt),
            )

        client = self.make_client(handler)

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(
                self.anchor,
                idempotency_key=self.anchor.digest,
            )

        self.assertEqual(
            len(self.requests),
            1,
            "The valid request should reach the mock provider",
        )

        self.assertEqual(
            self.requests[0].headers["Idempotency-Key"],
            self.anchor.digest,
        )

    def test_matching_receipt_digest_is_accepted(self):
        matching_receipt = create_signed_receipt(
            provider_id="example-provider",
            anchor_digest=self.anchor.digest,
            external_reference="matching-anchor-reference",
            observed_at="2026-11-01T12:00:00Z",
            secret=SECRET,
        )

        def handler(request):
            self.requests.append(request)

            return httpx.Response(
                201,
                headers={
                    "Content-Type": "application/json",
                },
                json=asdict(matching_receipt),
            )

        client = self.make_client(handler)

        receipt = client.publish(
            self.anchor,
            idempotency_key=self.anchor.digest,
        )

        self.assertEqual(
            receipt.anchor_digest,
            self.anchor.digest,
        )

        self.assertEqual(len(self.requests), 1)

    def test_http_409_is_classified_as_request_in_progress(self):
        def handler(request):
            self.requests.append(request)
            return httpx.Response(409)

        client = self.make_client(handler)

        with self.assertRaises(TrustedAnchorApiRequestInProgress):
            client.publish(
                self.anchor,
                idempotency_key=self.anchor.digest,
            )

        self.assertEqual(len(self.requests), 1)
        self.assertEqual(
            self.requests[0].headers["Idempotency-Key"],
            self.anchor.digest,
        )

    def test_http_422_is_classified_as_idempotency_conflict(self):
        def handler(request):
            self.requests.append(request)
            return httpx.Response(422)

        client = self.make_client(handler)

        with self.assertRaises(TrustedAnchorApiIdempotencyConflict):
            client.publish(
                self.anchor,
                idempotency_key=self.anchor.digest,
            )

        self.assertEqual(len(self.requests), 1)
        self.assertEqual(
            self.requests[0].headers["Idempotency-Key"],
            self.anchor.digest,
        )


if __name__ == "__main__":
    unittest.main()
