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
from jas_si_agent.trusted_anchor_api_backend import (
    TrustedAnchorApiBackendAdapter,
)
from jas_si_agent.trusted_anchor_api_client import (
    TrustedAnchorApiClient,
)
from jas_si_agent.trusted_anchor_api_contract import (
    TrustedAnchorApiContract,
)
from jas_si_agent.trusted_anchor_api_provider import (
    HmacReceiptVerifier,
)
from jas_si_agent.trusted_anchor_api_recovery import (
    RecoverableApiTrustedAnchorProvider,
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
from jas_si_agent.trusted_anchor_recovery import (
    recover_or_publish_anchor,
)


SECRET = b"test-api-backend-secret-minimum-32-bytes"
TOKEN = "test-api-token-value-123456789"


class TestTrustedAnchorApiBackendIntegration(unittest.TestCase):

    def setUp(self):
        self.profile = TrustedAnchorProviderProfile(
            provider_id="example-provider",
            base_url="https://anchors.example.com",
        )

        self.anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=12,
            last_hash="a" * 64,
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

        self.receipt = create_signed_receipt(
            provider_id="example-provider",
            anchor_digest=self.anchor.digest,
            external_reference="external-anchor-123",
            observed_at="2026-11-01T10:00:00Z",
            secret=SECRET,
        )

        self.published = False
        self.publish_requests = 0
        self.lookup_requests = 0

    def make_handler(self, request):
        if request.method == "GET":
            self.lookup_requests += 1

            if not self.published:
                return httpx.Response(404)

            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=asdict(self.receipt),
            )

        if request.method == "POST":
            self.publish_requests += 1

            self.assertEqual(
                request.headers["Idempotency-Key"],
                self.anchor.digest,
            )

            self.published = True

            return httpx.Response(
                201,
                headers={"Content-Type": "application/json"},
                json=asdict(self.receipt),
            )

        return httpx.Response(405)

    def make_provider(self):
        http_client = httpx.Client(
            transport=httpx.MockTransport(self.make_handler),
            follow_redirects=False,
        )

        transport = TrustedAnchorHttpTransport(
            self.profile,
            client=http_client,
        )

        api_client = TrustedAnchorApiClient(
            self.profile,
            transport,
            bearer_token=TOKEN,
            contract=self.contract,
        )

        backend = TrustedAnchorApiBackendAdapter(api_client)

        provider = RecoverableApiTrustedAnchorProvider(
            backend,
            HmacReceiptVerifier(SECRET),
            expected_provider_id="example-provider",
        )

        return provider, http_client

    def test_recovery_publishes_when_lookup_returns_not_found(self):
        provider, http_client = self.make_provider()

        try:
            receipt = recover_or_publish_anchor(
                provider,
                self.anchor,
            )

            self.assertEqual(
                receipt.anchor_digest,
                self.anchor.digest,
            )
            self.assertTrue(self.published)
            self.assertEqual(self.lookup_requests, 1)
            self.assertEqual(self.publish_requests, 1)

        finally:
            http_client.close()

    def test_recovery_reuses_existing_receipt_without_republishing(self):
        provider, http_client = self.make_provider()

        try:
            first = recover_or_publish_anchor(
                provider,
                self.anchor,
            )

            second = recover_or_publish_anchor(
                provider,
                self.anchor,
            )

            self.assertEqual(first, second)
            self.assertEqual(self.lookup_requests, 2)
            self.assertEqual(self.publish_requests, 1)

        finally:
            http_client.close()

    def test_recovery_fails_closed_when_lookup_server_fails(self):
        def broken_handler(request):
            return httpx.Response(503)

        http_client = httpx.Client(
            transport=httpx.MockTransport(broken_handler),
            follow_redirects=False,
        )

        transport = TrustedAnchorHttpTransport(
            self.profile,
            client=http_client,
        )

        api_client = TrustedAnchorApiClient(
            self.profile,
            transport,
            bearer_token=TOKEN,
            contract=self.contract,
        )

        backend = TrustedAnchorApiBackendAdapter(api_client)

        provider = RecoverableApiTrustedAnchorProvider(
            backend,
            HmacReceiptVerifier(SECRET),
            expected_provider_id="example-provider",
        )

        try:
            with self.assertRaises(Exception):
                recover_or_publish_anchor(
                    provider,
                    self.anchor,
                )

        finally:
            http_client.close()

    def test_recovers_when_publish_succeeds_but_response_is_lost(self):
        first_publish_attempt = True

        def flaky_handler(request):
            nonlocal first_publish_attempt

            if request.method == "POST" and first_publish_attempt:
                first_publish_attempt = False

                # Simulate remote persistence before response loss.
                self.make_handler(request)

                raise httpx.ReadTimeout(
                    "Simulated response loss after remote persistence"
                )

            return self.make_handler(request)

        http_client = httpx.Client(
            transport=httpx.MockTransport(flaky_handler),
            follow_redirects=False,
        )

        transport = TrustedAnchorHttpTransport(
            self.profile,
            client=http_client,
        )

        api_client = TrustedAnchorApiClient(
            self.profile,
            transport,
            bearer_token=TOKEN,
            contract=self.contract,
        )

        backend = TrustedAnchorApiBackendAdapter(api_client)

        provider = RecoverableApiTrustedAnchorProvider(
            backend,
            HmacReceiptVerifier(SECRET),
            expected_provider_id="example-provider",
        )

        try:
            # First attempt: remote publication happens,
            # but the client receives a timeout.
            with self.assertRaises(Exception):
                recover_or_publish_anchor(
                    provider,
                    self.anchor,
                )

            self.assertTrue(self.published)
            self.assertEqual(self.publish_requests, 1)

            # Second attempt: lookup must recover the existing receipt.
            recovered = recover_or_publish_anchor(
                provider,
                self.anchor,
            )

            self.assertEqual(
                recovered.anchor_digest,
                self.anchor.digest,
            )
            self.assertEqual(self.lookup_requests, 2)
            self.assertEqual(self.publish_requests, 1)

        finally:
            http_client.close()


if __name__ == "__main__":
    unittest.main()
