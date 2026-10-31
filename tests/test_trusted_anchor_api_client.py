from __future__ import annotations

import json
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


class TestTrustedAnchorApiClient(unittest.TestCase):

    TOKEN = "test-token-value-123456789"

    def setUp(self):
        self.profile = TrustedAnchorProviderProfile(
            provider_id="example-provider",
            base_url="https://anchors.example.com",
        )

        self.anchor = SecurityCheckpointAnchor(
            repository_id="jas-si",
            event_count=1,
            last_hash="a" * 64,
        )

    def make_receipt(self, **overrides):
        data = {
            "provider_id": "example-provider",
            "anchor_digest": self.anchor.digest,
            "external_reference": "anchor-123",
            "observed_at": "2026-10-31T12:00:00Z",
            "proof": "proof-value",
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
        )

        return client, http_client

    def make_contract(self, **overrides):
        values = {
            "publish_path": "v1/anchors",
            "lookup_path_template": (
                "v1/anchors/by-key/{idempotency_key}"
            ),
            "idempotency_header": "Idempotency-Key",
            "success_status_codes": (200, 201, 202),
        }
        values.update(overrides)
        return TrustedAnchorApiContract(**values)

    def make_contract_client(self, handler, contract=None):
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
            contract=contract or self.make_contract(),
        )

        return client, http_client

    def test_successful_authenticated_publish(self):
        def handler(request):
            self.assertEqual(
                request.headers["Authorization"],
                f"Bearer {self.TOKEN}",
            )
            self.assertEqual(
                request.headers["Content-Type"],
                "application/json",
            )

            submitted = json.loads(request.content)
            self.assertEqual(
                submitted["anchor_digest"],
                self.anchor.digest,
            )

            return httpx.Response(
                201,
                headers={"Content-Type": "application/json"},
                json=self.make_receipt(),
            )

        client, http_client = self.make_client(handler)

        receipt = client.publish(self.anchor)

        self.assertEqual(
            receipt.provider_id,
            "example-provider",
        )
        self.assertEqual(
            receipt.anchor_digest,
            self.anchor.digest,
        )

        http_client.close()

    def test_rejects_invalid_bearer_token(self):
        http_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200)
            )
        )

        transport = TrustedAnchorHttpTransport(
            self.profile,
            client=http_client,
        )

        for token in ("", "short", "token with spaces", "bad\nheader"):
            with self.subTest(token=repr(token)):
                with self.assertRaises(TrustedAnchorApiClientError):
                    TrustedAnchorApiClient(
                        self.profile,
                        transport,
                        bearer_token=token,
                    )

        http_client.close()

    def test_rejects_unexpected_http_status(self):
        client, http_client = self.make_client(
            lambda request: httpx.Response(500)
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(self.anchor)

        http_client.close()

    def test_rejects_non_json_content_type(self):
        client, http_client = self.make_client(
            lambda request: httpx.Response(
                200,
                headers={"Content-Type": "text/plain"},
                content=b"not json",
            )
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(self.anchor)

        http_client.close()

    def test_rejects_malformed_json(self):
        client, http_client = self.make_client(
            lambda request: httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=b"{invalid",
            )
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(self.anchor)

        http_client.close()

    def test_rejects_duplicate_json_keys(self):
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
            client.publish(self.anchor)

        http_client.close()

    def test_rejects_missing_receipt_fields(self):
        data = self.make_receipt()
        del data["proof"]

        client, http_client = self.make_client(
            lambda request: httpx.Response(
                201,
                headers={"Content-Type": "application/json"},
                json=data,
            )
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(self.anchor)

        http_client.close()

    def test_rejects_wrong_provider_id(self):
        client, http_client = self.make_client(
            lambda request: httpx.Response(
                201,
                headers={"Content-Type": "application/json"},
                json=self.make_receipt(
                    provider_id="untrusted-provider"
                ),
            )
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(self.anchor)

        http_client.close()

    def test_rejects_wrong_anchor_digest(self):
        client, http_client = self.make_client(
            lambda request: httpx.Response(
                201,
                headers={"Content-Type": "application/json"},
                json=self.make_receipt(
                    anchor_digest="b" * 64
                ),
            )
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(self.anchor)

        http_client.close()

    def test_contract_publish_sends_idempotency_header(self):
        def handler(request):
            self.assertEqual(
                request.url.path,
                "/v1/anchors",
            )
            self.assertEqual(
                request.headers["Idempotency-Key"],
                self.anchor.digest,
            )
            return httpx.Response(
                201,
                headers={"Content-Type": "application/json"},
                json=self.make_receipt(),
            )

        client, http_client = self.make_contract_client(handler)

        receipt = client.publish(
            self.anchor,
            idempotency_key=self.anchor.digest,
        )

        self.assertEqual(receipt.anchor_digest, self.anchor.digest)
        http_client.close()

    def test_contract_publish_uses_configured_path(self):
        contract = self.make_contract(
            publish_path="api/v2/checkpoints",
        )

        def handler(request):
            self.assertEqual(
                request.url.path,
                "/api/v2/checkpoints",
            )
            return httpx.Response(
                201,
                headers={"Content-Type": "application/json"},
                json=self.make_receipt(),
            )

        client, http_client = self.make_contract_client(
            handler,
            contract,
        )

        client.publish(
            self.anchor,
            idempotency_key=self.anchor.digest,
        )

        http_client.close()

    def test_contract_publish_accepts_configured_status(self):
        contract = self.make_contract(
            success_status_codes=(202,),
        )

        client, http_client = self.make_contract_client(
            lambda request: httpx.Response(
                202,
                headers={"Content-Type": "application/json"},
                json=self.make_receipt(),
            ),
            contract,
        )

        receipt = client.publish(
            self.anchor,
            idempotency_key=self.anchor.digest,
        )

        self.assertEqual(receipt.anchor_digest, self.anchor.digest)
        http_client.close()

    def test_contract_publish_requires_idempotency_key(self):
        client, http_client = self.make_contract_client(
            lambda request: httpx.Response(500),
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(self.anchor)

        http_client.close()

    def test_contract_publish_rejects_wrong_idempotency_key(self):
        client, http_client = self.make_contract_client(
            lambda request: httpx.Response(500),
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(
                self.anchor,
                idempotency_key="b" * 64,
            )

        http_client.close()

    def test_idempotency_key_requires_contract(self):
        client, http_client = self.make_client(
            lambda request: httpx.Response(500),
        )

        with self.assertRaises(TrustedAnchorApiClientError):
            client.publish(
                self.anchor,
                idempotency_key=self.anchor.digest,
            )

        http_client.close()


if __name__ == "__main__":
    unittest.main()
