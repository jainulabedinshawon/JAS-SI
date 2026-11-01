
from __future__ import annotations

import sys
import unittest
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
)
from jas_si_agent.trusted_anchor_api_contract import (
    TrustedAnchorApiContract,
)
from jas_si_agent.trusted_anchor_http_transport import (
    TrustedAnchorHttpTransport,
)
from jas_si_agent.trusted_anchor_provider_profile import (
    TrustedAnchorProviderProfile,
)


class TestTrustedAnchorApiIdempotencyGuards(unittest.TestCase):

    TOKEN = "test-token-value-123456789"

    def setUp(self):
        self.profile = TrustedAnchorProviderProfile(
            provider_id="example-provider",
            base_url="https://anchors.example.com",
        )

        self.anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=31,
            last_hash="e" * 64,
        )

        self.requests = []

    def make_client(self, *, contract=None):
        def handler(request):
            self.requests.append(request)
            return httpx.Response(500)

        self.http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        )

        transport = TrustedAnchorHttpTransport(
            self.profile,
            client=self.http_client,
        )

        client = TrustedAnchorApiClient(
            self.profile,
            transport,
            bearer_token=self.TOKEN,
            contract=contract,
        )

        return client

    def tearDown(self):
        if hasattr(self, "http_client"):
            self.http_client.close()

    def make_contract(self):
        return TrustedAnchorApiContract(
            publish_path="v1/anchors",
            lookup_path_template=(
                "v1/anchors/by-key/{idempotency_key}"
            ),
            idempotency_header="Idempotency-Key",
            success_status_codes=(200, 201),
            lookup_not_found_status_code=404,
        )

    def test_wrong_key_is_rejected_before_network_request(self):
        client = self.make_client(
            contract=self.make_contract(),
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(
                self.anchor,
                idempotency_key="a" * 64,
            )

        self.assertEqual(
            len(self.requests),
            0,
            "Invalid idempotency key must not reach the network",
        )

    def test_missing_key_is_rejected_before_network_request(self):
        client = self.make_client(
            contract=self.make_contract(),
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(self.anchor)

        self.assertEqual(
            len(self.requests),
            0,
            "Missing idempotency key must not reach the network",
        )

    def test_key_without_contract_is_rejected_before_network_request(self):
        client = self.make_client()

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(
                self.anchor,
                idempotency_key=self.anchor.digest,
            )

        self.assertEqual(
            len(self.requests),
            0,
            "Idempotency key without explicit contract must not reach network",
        )

    def test_valid_key_is_bound_to_anchor_digest(self):
        client = self.make_client(
            contract=self.make_contract(),
        )

        # The mock server deliberately returns an error.
        # Reaching it proves local validation accepted the request.
        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(
                self.anchor,
                idempotency_key=self.anchor.digest,
            )

        self.assertEqual(len(self.requests), 1)

        request = self.requests[0]

        self.assertEqual(request.method, "POST")
        self.assertEqual(
            request.headers["Idempotency-Key"],
            self.anchor.digest,
        )
        self.assertEqual(
            request.url.path,
            "/v1/anchors",
        )


if __name__ == "__main__":
    unittest.main()
