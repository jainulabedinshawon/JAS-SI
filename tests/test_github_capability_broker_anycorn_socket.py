"""Real Anycorn TLS socket -> actual JAS-SI Broker ASGI app integration.

The test server dependency is isolated to CI and installed from an ephemeral
hash-locked resolution. It is not added to the production runtime lock.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

try:
    import anycorn as _anycorn  # noqa: F401
except ImportError:
    ANYCORN_AVAILABLE = False
else:
    ANYCORN_AVAILABLE = True

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from jas_si_agent.config import Settings
from jas_si_agent.github_capability_identity import (
    CertificateWorkloadIdentityRegistry,
    WorkloadIdentity,
)
from jas_si_agent.github_capability_runtime import create_github_capability_app


class _FakeBroker:
    """Keep the test at the ASGI identity boundary without a live database."""

    def resolve(self, **kwargs):
        return SimpleNamespace(
            task_id=kwargs["task_id"],
            tenant_id=uuid4(),
            installation_id=123456,
            repository_full_name="owner/private-repo",
            capability_role=kwargs["role"],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            commit_sha="a" * 40,
            repository_paths=["src/allowed.py"],
        )


class _LazyBrokerApp:
    """Build the real Broker ASGI app inside the child server process."""

    def __init__(self):
        self._app = None

    async def __call__(self, scope, receive, send):
        if self._app is None:
            fingerprint = os.environ["JAS_SI_TEST_CLIENT_FINGERPRINT"]
            registry = CertificateWorkloadIdentityRegistry({
                fingerprint: WorkloadIdentity(
                    "worker.staging.asgi-socket-test", "worker"
                )
            })
            settings = Settings(
                environment="preview",
                github_capability_broker_enabled=True,
                github_capability_broker_database_url=(
                    "postgresql://broker:unused@127.0.0.1:1/jas_si_test?sslmode=verify-full"
                ),
                github_capability_workload_identities=registry,
            )
            self._app = create_github_capability_app(
                settings, broker_factory=lambda _dsn: _FakeBroker()
            )
        await self._app(scope, receive, send)


# Anycorn imports this object in its independent server process.
app = _LazyBrokerApp()


def _make_ca(common_name: str):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=2))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _issue_leaf(ca_key, ca_cert, common_name: str, *, client: bool):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH if client
            else ExtendedKeyUsageOID.SERVER_AUTH
        ]), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
    )
    if not client:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))


def _write_cert(path: Path, cert) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


@unittest.skipUnless(ANYCORN_AVAILABLE, "Anycorn is installed only in the dedicated Broker ASGI CI job")
class BrokerAnycornASGISocketIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        ca_key, ca_cert = _make_ca("JAS-SI integration test CA")
        server_key, server_cert = _issue_leaf(
            ca_key, ca_cert, "localhost", client=False
        )
        client_key, client_cert = _issue_leaf(
            ca_key, ca_cert, "jas-si-worker-test", client=True
        )
        untrusted_ca_key, untrusted_ca_cert = _make_ca(
            "JAS-SI untrusted test CA"
        )
        untrusted_key, untrusted_cert = _issue_leaf(
            untrusted_ca_key, untrusted_ca_cert,
            "jas-si-untrusted-worker-test", client=True,
        )

        cls.ca_path = root / "test-ca.pem"
        cls.server_cert_path = root / "server-cert.pem"
        cls.server_key_path = root / "server-key.pem"
        cls.client_cert_path = root / "client-cert.pem"
        cls.client_key_path = root / "client-key.pem"
        cls.untrusted_cert_path = root / "untrusted-cert.pem"
        cls.untrusted_key_path = root / "untrusted-key.pem"
        _write_cert(cls.ca_path, ca_cert)
        _write_cert(cls.server_cert_path, server_cert)
        _write_key(cls.server_key_path, server_key)
        _write_cert(cls.client_cert_path, client_cert)
        _write_key(cls.client_key_path, client_key)
        _write_cert(cls.untrusted_cert_path, untrusted_cert)
        _write_key(cls.untrusted_key_path, untrusted_key)
        cls.client_pem = cls.client_cert_path.read_text()
        cls.client_fingerprint = client_cert.fingerprint(hashes.SHA256()).hex()

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            cls.port = probe.getsockname()[1]

        repo_root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join([
            str(repo_root / "src"), str(repo_root / "tests"),
        ])
        env["JAS_SI_TEST_CLIENT_FINGERPRINT"] = cls.client_fingerprint
        server_script = (
            "import ssl, anyio; "
            "from anycorn import Config, serve; "
            "from test_github_capability_broker_anycorn_socket import app; "
            "config = Config(); "
            f"config.bind = ['127.0.0.1:{cls.port}']; "
            f"config.certfile = {str(cls.server_cert_path)!r}; "
            f"config.keyfile = {str(cls.server_key_path)!r}; "
            f"config.ca_certs = {str(cls.ca_path)!r}; "
            "config.verify_mode = ssl.CERT_REQUIRED; "
            "config.alpn_protocols = ['http/1.1']; "
            "config.daemon = False; config.workers = 1; "
            "config.errorlog = None; config.accesslog = None; "
            "anyio.run(serve, app, config)"
        )
        cls.server_log_path = root / "anycorn-server.log"
        cls.server_log_handle = cls.server_log_path.open("w+", encoding="utf-8")
        cls.server = subprocess.Popen(
            [sys.executable, "-c", server_script],
            cwd=str(repo_root),
            env=env,
            stdout=cls.server_log_handle,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if cls.server.poll() is not None:
                cls.server_log_handle.flush()
                raise RuntimeError(
                    "Anycorn Broker ASGI test server exited during startup: "
                    + cls.server_log_path.read_text(encoding="utf-8")[-8000:]
                )
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            cls.server.terminate()
            raise RuntimeError("Anycorn Broker ASGI test server did not become ready")

    @classmethod
    def tearDownClass(cls):
        server = getattr(cls, "server", None)
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        log_handle = getattr(cls, "server_log_handle", None)
        if log_handle is not None:
            log_handle.close()
        temp = getattr(cls, "temp", None)
        if temp is not None:
            temp.cleanup()

    def _request(self, *, cert=None, key=None, extra_headers=None):
        context = ssl.create_default_context(cafile=str(self.ca_path))
        if cert is not None and key is not None:
            context.load_cert_chain(str(cert), str(key))
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.port, context=context, timeout=5
        )
        body = json.dumps({
            "task_id": str(uuid4()),
            "lease_fence": 1,
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        headers.update(extra_headers or {})
        try:
            connection.request(
                "POST", "/internal/github/capabilities/resolve",
                body=body, headers=headers,
            )
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_valid_mtls_peer_reaches_actual_broker_asgi_route(self):
        status, body = self._request(
            cert=self.client_cert_path, key=self.client_key_path
        )
        self.assertEqual(status, 200, body.decode("utf-8"))
        payload = json.loads(body)
        self.assertEqual(payload["repository"], "owner/private-repo")
        self.assertEqual(payload["capability_role"], "worker")
        self.assertNotIn("access_token", payload)

    def test_missing_client_certificate_is_rejected_before_asgi(self):
        with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
            self._request()

    def test_untrusted_client_certificate_is_rejected_before_asgi(self):
        with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
            self._request(
                cert=self.untrusted_cert_path, key=self.untrusted_key_path
            )

    def test_spoofed_certificate_headers_without_mtls_are_rejected(self):
        with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
            self._request(extra_headers={
                "X-Client-Cert": "forged-certificate",
                "X-Workload-Principal": "worker.staging.asgi-socket-test",
            })


if __name__ == "__main__":
    unittest.main(verbosity=2)
