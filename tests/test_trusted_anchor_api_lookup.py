
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


class TestTrustedAnchorApiLookup(unittest.TestCase):

    TOKEN = "test-token-value-123456789"

    def setUp(self):
        self.profile = TrustedAnchorProviderProfile(
            provider_id="example-provider",
            base_url="https://anchors.example.com",
        )

        self.anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=10,
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

    def make_receipt(self, **overrides):
        data = {
            "provider_id": "example-provider",
            "anchor_digest": self.anchor.digest,
            "external_reference": "external-anchor-123",
            "observed_at": "2026-10-31T12:00:00Z",
            "proof": "test-proof",
        }
        data.update(overrides)
        return data

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
            bearer_token=self.TOKEN,
            contract=self.contract,
        )

        return client, http_client

    def test_lookup_returns_existing_receipt(self):
        def handler(request):
            self.assertEqual(request.method, "GET")
            self.assertEqual(
                request.url.path,
                f"/v1/anchors/by-key/{self.anchor.digest}",
            )
            self.assertEqual(
                request.headers["Authorization"],
                f"Bearer {self.TOKEN}",
            )

            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=self.make_receipt(),
            )

        client, http_client = self.make_client(handler)

        receipt = client.lookup_by_idempotency_key(
            self.anchor.digest
        )

        self.assertIsNotNone(receipt)
        self.assertEqual(
            receipt.anchor_digest,
            self.anchor.digest,
        )

        http_client.close()

    def test_lookup_returns_none_on_configured_not_found(self):
        client, http_client = self.make_client(
            lambda request: httpx.Response(404)
        )

        result = client.lookup_by_idempotency_key(
            self.anchor.digest
        )

        self.assertIsNone(result)
        http_client.close()

    def test_lookup_rejects_invalid_key(self):
        client, http_client = self.make_client(
            lambda request: httpx.Response(404)
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.lookup_by_idempotency_key("../invalid")

        http_client.close()

    def test_lookup_rejects_wrong_provider(self):
        client, http_client = self.make_client(
            lambda request: httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=self.make_receipt(
                    provider_id="attacker-provider"
                ),
            )
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.lookup_by_idempotency_key(
                self.anchor.digest
            )

        http_client.close()

    def test_lookup_rejects_wrong_digest(self):
        client, http_client = self.make_client(
            lambda request: httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json=self.make_receipt(
                    anchor_digest="b" * 64
                ),
            )
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.lookup_by_idempotency_key(
                self.anchor.digest
            )

        http_client.close()

    def test_lookup_rejects_server_error(self):
        client, http_client = self.make_client(
            lambda request: httpx.Response(500)
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.lookup_by_idempotency_key(
                self.anchor.digest
            )

        http_client.close()

    def test_lookup_rejects_non_json_response(self):
        client, http_client = self.make_client(
            lambda request: httpx.Response(
                200,
                headers={"Content-Type": "text/plain"},
                content=b"not json",
            )
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.lookup_by_idempotency_key(
                self.anchor.digest
            )

        http_client.close()

    def test_lookup_rejects_duplicate_json_keys(self):
        body = (
            '{"provider_id":"example-provider",'
            '"provider_id":"attacker",'
            '"anchor_digest":"' + self.anchor.digest + '",'
            '"external_reference":"ref",'
            '"observed_at":"2026-10-31T12:00:00Z",'
            '"proof":"proof"}'
        )

        client, http_client = self.make_client(
            lambda request: httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=body.encode("utf-8"),
            )
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.lookup_by_idempotency_key(
                self.anchor.digest
            )

        http_client.close()


if __name__ == "__main__":
    unittest.main()
