"""Adversarial contract tests for the ASGI TLS client-certificate boundary."""
from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from jas_si_agent.github_capability_asgi_tls import (
    ASGITLSClientCertificateMiddleware,
)


def _client_certificate_pem() -> str:
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "jas-si-test-client")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(minutes=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(hours=1)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


class ASGITLSClientCertificateMiddlewareTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, scope: dict):
        captured = {}

        async def app(inner_scope, receive, send):
            captured["state"] = inner_scope["state"]
            captured["scope"] = inner_scope

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            return None

        middleware = ASGITLSClientCertificateMiddleware(app)
        await middleware(scope, receive, send)
        return captured

    async def test_valid_tls_extension_attaches_exact_leaf_der(self):
        pem = _client_certificate_pem()
        captured = await self._run({
            "type": "http",
            "extensions": {
                "tls": {"spec_version": "0.3", "client_cert_chain": [pem]}
            },
            "state": {},
        })
        actual = captured["state"]["verified_client_certificate_der"]
        expected = x509.load_pem_x509_certificate(pem.encode("ascii")).public_bytes(
            serialization.Encoding.DER
        )
        self.assertEqual(actual, expected)

    async def test_http_certificate_header_is_never_a_fallback(self):
        pem = _client_certificate_pem()
        state = {"verified_client_certificate_der": b"stale-or-forged"}
        captured = await self._run({
            "type": "http",
            "headers": [(b"x-client-cert", pem.encode("ascii"))],
            "state": state,
        })
        self.assertNotIn("verified_client_certificate_der", captured["state"])

    async def test_explicit_tls_verification_error_is_rejected(self):
        captured = await self._run({
            "type": "http",
            "extensions": {
                "tls": {
                    "spec_version": "0.2",
                    "client_cert_error": "certificate verify failed",
                    "client_cert_chain": [_client_certificate_pem()],
                }
            },
            "state": {},
        })
        self.assertNotIn("verified_client_certificate_der", captured["state"])

    async def test_unsupported_tls_extension_version_is_rejected(self):
        captured = await self._run({
            "type": "http",
            "extensions": {
                "tls": {"spec_version": "9.9", "client_cert_chain": [_client_certificate_pem()]}
            },
            "state": {},
        })
        self.assertNotIn("verified_client_certificate_der", captured["state"])

    async def test_non_pem_and_non_iterable_certificate_chains_are_rejected(self):
        for chain in (b"not-a-chain", ["not-a-certificate"]):
            with self.subTest(chain=type(chain).__name__):
                captured = await self._run({
                    "type": "http",
                    "extensions": {"tls": {"spec_version": "0.3", "client_cert_chain": chain}},
                    "state": {},
                })
                self.assertNotIn("verified_client_certificate_der", captured["state"])

    async def test_oversized_certificate_chain_is_rejected(self):
        pem = _client_certificate_pem()
        captured = await self._run({
            "type": "http",
            "extensions": {
                "tls": {"spec_version": "0.3", "client_cert_chain": [pem] * 9}
            },
            "state": {},
        })
        self.assertNotIn("verified_client_certificate_der", captured["state"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
