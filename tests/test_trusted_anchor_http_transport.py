from __future__ import annotations

import sys
import unittest
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.trusted_anchor_http_transport import (
    TrustedAnchorHttpTransport,
    TrustedAnchorHttpTransportError,
)
from jas_si_agent.trusted_anchor_provider_profile import (
    TrustedAnchorProviderProfile,
)


class TestTrustedAnchorHttpTransport(unittest.TestCase):

    def make_profile(self, **overrides):
        values = {
            "provider_id": "example-provider",
            "base_url": "https://anchors.example.com",
            "max_response_bytes": 1024,
        }
        values.update(overrides)
        return TrustedAnchorProviderProfile(**values)

    def make_client(self, handler):
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        )

    def test_successful_https_request(self):
        def handler(request):
            self.assertEqual(request.url.scheme, "https")
            self.assertEqual(request.url.path, "/v1/anchors")

            return httpx.Response(
                200,
                content=b'{"verified": true}',
            )

        client = self.make_client(handler)
        transport = TrustedAnchorHttpTransport(
            self.make_profile(),
            client=client,
        )

        response = transport.request("GET", "v1/anchors")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, b'{"verified": true}')

        client.close()

    def test_rejects_absolute_url(self):
        client = self.make_client(
            lambda request: httpx.Response(200)
        )

        transport = TrustedAnchorHttpTransport(
            self.make_profile(),
            client=client,
        )

        with self.assertRaises(TrustedAnchorHttpTransportError):
            transport.request(
                "GET",
                "https://evil.example.com/steal",
            )

        client.close()

    def test_rejects_path_traversal(self):
        client = self.make_client(
            lambda request: httpx.Response(200)
        )

        transport = TrustedAnchorHttpTransport(
            self.make_profile(),
            client=client,
        )

        with self.assertRaises(TrustedAnchorHttpTransportError):
            transport.request("GET", "../admin")

        client.close()

    def test_rejects_query_in_path(self):
        client = self.make_client(
            lambda request: httpx.Response(200)
        )

        transport = TrustedAnchorHttpTransport(
            self.make_profile(),
            client=client,
        )

        with self.assertRaises(TrustedAnchorHttpTransportError):
            transport.request("GET", "v1/anchors?token=secret")

        client.close()

    def test_does_not_follow_redirects(self):
        def handler(request):
            return httpx.Response(
                302,
                headers={
                    "Location": "https://evil.example.com/redirect"
                },
            )

        client = self.make_client(handler)

        transport = TrustedAnchorHttpTransport(
            self.make_profile(),
            client=client,
        )

        response = transport.request("GET", "v1/anchors")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers["location"],
            "https://evil.example.com/redirect",
        )

        client.close()

    def test_rejects_oversized_response(self):
        def handler(request):
            return httpx.Response(
                200,
                content=b"x" * 2048,
            )

        client = self.make_client(handler)

        transport = TrustedAnchorHttpTransport(
            self.make_profile(max_response_bytes=1024),
            client=client,
        )

        with self.assertRaises(TrustedAnchorHttpTransportError):
            transport.request("GET", "v1/anchors")

        client.close()

    def test_sends_post_body(self):
        def handler(request):
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.content, b'{"anchor": "test"}')

            return httpx.Response(201, content=b"created")

        client = self.make_client(handler)

        transport = TrustedAnchorHttpTransport(
            self.make_profile(),
            client=client,
        )

        response = transport.request(
            "POST",
            "v1/anchors",
            headers={"Content-Type": "application/json"},
            content=b'{"anchor": "test"}',
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.body, b"created")

        client.close()

    def test_rejects_non_bytes_content(self):
        client = self.make_client(
            lambda request: httpx.Response(200)
        )

        transport = TrustedAnchorHttpTransport(
            self.make_profile(),
            client=client,
        )

        with self.assertRaises(TrustedAnchorHttpTransportError):
            transport.request(
                "POST",
                "v1/anchors",
                content="not bytes",
            )

        client.close()


if __name__ == "__main__":
    unittest.main()
