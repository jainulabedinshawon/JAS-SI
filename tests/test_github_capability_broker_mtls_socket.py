"""Real loopback TLS handshake tests for the isolated GitHub Broker listener.

These tests prove certificate-required transport behavior at TCP/TLS level.
They do not claim to deploy a listener or configure a cloud runtime.
"""
from __future__ import annotations

import asyncio
import ipaddress
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _certificate_pair(directory: Path, *, client: bool, trusted: bool = True):
    """Create ephemeral CA + leaf certificates for a localhost test."""
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "JAS-SI test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(minutes=2)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(hours=2)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .key_usage(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME, "jas-si-test-client" if client else "localhost"
    )])
    builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(minutes=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(hours=1)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH if client
                else ExtendedKeyUsageOID.SERVER_AUTH
            ]), critical=True,
        )
    )
    if not client:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]), critical=False,
        )
    leaf = builder.sign(ca_key, hashes.SHA256())

    def write(name: str, data: bytes) -> Path:
        path = directory / name
        path.write_bytes(data)
        return path

    ca_path = write("ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    cert_path = write("leaf.pem", leaf.public_bytes(serialization.Encoding.PEM))
    key_path = write("leaf-key.pem", leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return ca_path, cert_path, key_path


class BrokerMTLSSocketIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def _handshake(self, *, provide_client_cert: bool, trusted_client: bool = True):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            server_ca, server_cert, server_key = _certificate_pair(root, client=False)
            client_ca, client_cert, client_key = _certificate_pair(
                root, client=True, trusted=trusted_client
            )

            server_context = __import__("ssl").create_default_context(
                __import__("ssl").Purpose.CLIENT_AUTH
            )
            server_context.load_cert_chain(server_cert, server_key)
            server_context.load_verify_locations(cafile=client_ca if trusted_client else server_ca)
            server_context.verify_mode = __import__("ssl").CERT_REQUIRED

            client_context = __import__("ssl").create_default_context(
                __import__("ssl").Purpose.SERVER_AUTH, cafile=server_ca
            )
            if provide_client_cert:
                client_context.load_cert_chain(client_cert, client_key)

            peer_seen = []

            async def handle(reader, writer):
                ssl_object = writer.get_extra_info("ssl_object")
                peer_seen.append(ssl_object.getpeercert(binary_form=True))
                writer.write(b"broker-listener-ready")
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_server(
                handle, "127.0.0.1", 0, ssl=server_context
            )
            port = server.sockets[0].getsockname()[1]
            try:
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", port, ssl=client_context,
                    server_hostname="localhost",
                )
                response = await reader.read(64)
                writer.close()
                await writer.wait_closed()
                return response, peer_seen
            finally:
                server.close()
                await server.wait_closed()

    async def test_valid_client_certificate_completes_real_tls_handshake(self):
        response, peer = await self._handshake(provide_client_cert=True)
        self.assertEqual(response, b"broker-listener-ready")
        self.assertEqual(len(peer), 1)
        self.assertIsInstance(peer[0], bytes)
        self.assertGreater(len(peer[0]), 0)

    async def test_client_without_certificate_is_rejected_by_cert_required(self):
        with self.assertRaises((OSError, __import__("ssl").SSLError)):
            await self._handshake(provide_client_cert=False)

    async def test_client_certificate_from_untrusted_ca_is_rejected(self):
        with self.assertRaises((OSError, __import__("ssl").SSLError)):
            await self._handshake(provide_client_cert=True, trusted_client=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
