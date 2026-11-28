"""Real loopback mTLS transport tests for the dedicated capability listener."""
from __future__ import annotations

import asyncio
import json
import os
import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import anyio
import httpx
from anycorn import serve
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from jas_si_agent.github_capability_tls_server import build_config


def _issue_certificate(ca_key, ca_cert, common_name, usage, *, san=None, is_ca=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject if ca_cert else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=2))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=1 if is_ca else None), critical=True)
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    if usage:
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))


def _write_cert(path: Path, cert) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


class CapabilityTlsListenerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "JAS-SI test workload CA")])
        now = datetime.now(timezone.utc)
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=2))
            .not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ), critical=True)
            .sign(self.ca_key, hashes.SHA256())
        )
        self.server_key, self.server_cert = _issue_certificate(
            self.ca_key, self.ca_cert, "localhost", ExtendedKeyUsageOID.SERVER_AUTH,
            san=[x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))],
        )
        self.client_key, self.client_cert = _issue_certificate(
            self.ca_key, self.ca_cert, "jas-si-test-worker", ExtendedKeyUsageOID.CLIENT_AUTH,
        )
        self.ca_path = self.directory / "ca.pem"
        self.server_cert_path = self.directory / "server.pem"
        self.server_key_path = self.directory / "server-key.pem"
        self.client_cert_path = self.directory / "client.pem"
        self.client_key_path = self.directory / "client-key.pem"
        _write_cert(self.ca_path, self.ca_cert)
        _write_cert(self.server_cert_path, self.server_cert)
        _write_key(self.server_key_path, self.server_key)
        _write_cert(self.client_cert_path, self.client_cert)
        _write_key(self.client_key_path, self.client_key)

    def tearDown(self):
        self.temp.cleanup()

    def _environment(self):
        return {
            "JAS_SI_CAPABILITY_TLS_SERVER_CERT": str(self.server_cert_path),
            "JAS_SI_CAPABILITY_TLS_SERVER_KEY": str(self.server_key_path),
            "JAS_SI_CAPABILITY_TLS_CLIENT_CA": str(self.ca_path),
            "JAS_SI_CAPABILITY_TLS_BIND_HOST": "127.0.0.1",
            "JAS_SI_CAPABILITY_TLS_BIND_PORT": "0",
        }

    def test_config_requires_client_certificate_and_strict_chain(self):
        with patch.dict(os.environ, self._environment(), clear=False):
            config = build_config()
        self.assertEqual(config.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(config.verify_flags, ssl.VERIFY_X509_STRICT)
        self.assertEqual(config.insecure_bind, [])
        context = config.create_ssl_context()
        self.assertIsNotNone(context)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_missing_ca_fails_closed_before_server_start(self):
        env = self._environment()
        env.pop("JAS_SI_CAPABILITY_TLS_CLIENT_CA")
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaisesRegex(RuntimeError, "JAS_SI_CAPABILITY_TLS_CLIENT_CA"):
                build_config()

    def test_live_anycorn_handshake_exposes_verified_peer_chain(self):
        async def test_server():
            async def probe_app(scope, receive, send):
                tls = scope.get("extensions", {}).get("tls", {})
                chain = tls.get("client_cert_chain", ())
                payload = json.dumps({"tls_extension": bool(tls), "chain_length": len(chain)})
                await send({"type": "http.response.start", "status": 200,
                            "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": payload.encode()})

            with patch.dict(os.environ, self._environment(), clear=False):
                config = build_config()
            config.bind = ["127.0.0.1:0"]
            async with anyio.create_task_group() as task_group:
                urls = await task_group.start(serve, probe_app, config)
                address = urls[0].removeprefix("https://")
                client_context = ssl.create_default_context(cafile=str(self.ca_path))
                client_context.load_cert_chain(str(self.client_cert_path), str(self.client_key_path))
                async with httpx.AsyncClient(verify=client_context, timeout=5) as client:
                    response = await client.get(f"https://{address}/")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json(), {"tls_extension": True, "chain_length": 1})
                task_group.cancel_scope.cancel()

        anyio.run(test_server)

    def test_live_listener_rejects_client_without_certificate(self):
        async def test_server():
            async def probe_app(scope, receive, send):
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b"unexpected"})

            with patch.dict(os.environ, self._environment(), clear=False):
                config = build_config()
            config.bind = ["127.0.0.1:0"]
            async with anyio.create_task_group() as task_group:
                urls = await task_group.start(serve, probe_app, config)
                address = urls[0].removeprefix("https://")
                client_context = ssl.create_default_context(cafile=str(self.ca_path))
                async with httpx.AsyncClient(verify=client_context, timeout=5) as client:
                    with self.assertRaises(httpx.ConnectError):
                        await client.get(f"https://{address}/")
                task_group.cancel_scope.cancel()

        anyio.run(test_server)


if __name__ == "__main__":
    unittest.main()
