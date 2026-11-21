"""Adversarial tests for the ASGI TLS client-certificate adapter."""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.github_capability_asgi_tls import (
    ASGITLSClientCertificateMiddleware,
)


class ASGITLSClientCertificateMiddlewareTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "jas-si-worker")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before((now - timedelta(minutes=1)).replace(tzinfo=None))
            .not_valid_after((now + timedelta(hours=1)).replace(tzinfo=None))
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        self.pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        self.der = certificate.public_bytes(serialization.Encoding.DER)

    async def _run(self, scope):
        captured = {}

        async def app(child_scope, receive, send):
            captured.update(child_scope)

        middleware = ASGITLSClientCertificateMiddleware(app)
        await middleware(scope, None, None)
        return captured

    async def test_tls_03_peer_leaf_is_attached_to_request_state(self):
        child = await self._run({
            "type": "http",
            "extensions": {"tls": {"spec_version": "0.3", "client_cert_chain": [self.pem]}},
            "state": {"request_id": "req-1"},
        })
        self.assertEqual(child["state"]["verified_client_certificate_der"], self.der)
        self.assertEqual(child["state"]["request_id"], "req-1")

    async def test_tls_02_peer_verification_error_is_rejected(self):
        child = await self._run({
            "type": "http",
            "extensions": {"tls": {
                "spec_version": "0.2",
                "client_cert_chain": [self.pem],
                "client_cert_error": "certificate verify failed",
            }},
        })
        self.assertNotIn("verified_client_certificate_der", child["state"])

    async def test_missing_tls_extension_does_not_accept_identity_header(self):
        child = await self._run({
            "type": "http",
            "headers": [(b"x-workload-identity", b"worker.staging.instance-1")],
            "state": {"verified_client_certificate_der": self.der},
        })
        self.assertNotIn("verified_client_certificate_der", child["state"])

    async def test_malformed_pem_and_unsupported_extension_are_rejected(self):
        malformed = await self._run({
            "type": "http",
            "extensions": {"tls": {"spec_version": "0.3", "client_cert_chain": ["not pem"]}},
        })
        unsupported = await self._run({
            "type": "http",
            "extensions": {"tls": {"spec_version": "9.9", "client_cert_chain": [self.pem]}},
        })
        self.assertNotIn("verified_client_certificate_der", malformed["state"])
        self.assertNotIn("verified_client_certificate_der", unsupported["state"])

    async def test_excessive_chain_is_rejected(self):
        child = await self._run({
            "type": "http",
            "extensions": {"tls": {
                "spec_version": "0.3",
                "client_cert_chain": [self.pem] * 9,
            }},
        })
        self.assertNotIn("verified_client_certificate_der", child["state"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
