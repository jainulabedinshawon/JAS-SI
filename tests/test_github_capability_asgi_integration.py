"""Exercise the isolated Broker ASGI app from TLS scope through DB resolver.

This is an ASGI-scope integration test, not proof of a real TLS listener or
certificate-chain validation. The real-socket listener test remains a
separate required deployment gate.
"""
from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from jas_si_agent.github_capability_identity import (
    CertificateWorkloadIdentityRegistry,
    WorkloadIdentity,
)
from jas_si_agent.github_capability_runtime import create_github_capability_app


def _client_cert():
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "jas-si-broker-asgi-test")
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(minutes=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(hours=1)).replace(tzinfo=None))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM), cert.public_bytes(
        serialization.Encoding.DER
    ), cert.fingerprint(hashes.SHA256()).hex()


class _Broker:
    def __init__(self):
        self.calls = []

    def resolve(self, **kwargs):
        self.calls.append(kwargs)
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


class GitHubCapabilityASGIIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def _request(self, app, *, tls=None, headers=None):
        body = json.dumps({
            "task_id": str(self.task_id),
            "lease_fence": 7,
        }).encode("utf-8")
        messages = [{"type": "http.request", "body": body, "more_body": False}]
        sent = []

        async def receive():
            if messages:
                return messages.pop(0)
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/internal/github/capabilities/resolve",
            "raw_path": b"/internal/github/capabilities/resolve",
            "query_string": b"",
            "root_path": "",
            "headers": headers or [(b"content-type", b"application/json")],
            "client": ("127.0.0.1", 43123),
            "server": ("127.0.0.1", 8443),
            "state": {},
        }
        if tls is not None:
            scope["extensions"] = {"tls": tls}
        await app(scope, receive, send)
        start = next(item for item in sent if item["type"] == "http.response.start")
        chunks = [
            item.get("body", b"")
            for item in sent
            if item["type"] == "http.response.body"
        ]
        return start["status"], b"".join(chunks)

    def setUp(self):
        self.task_id = uuid4()
        pem, self.der, fingerprint = _client_cert()
        self.pem = pem
        self.registry = CertificateWorkloadIdentityRegistry({
            fingerprint: WorkloadIdentity("worker.staging.asgi-test", "worker")
        })
        self.broker = _Broker()
        settings = SimpleNamespace(
            github_capability_broker_enabled=True,
            environment="preview",
            github_capability_broker_database_url=(
                "postgresql://broker:secret@db.example.test/db?sslmode=verify-full"
            ),
            github_capability_workload_identities=self.registry,
        )
        self.app = create_github_capability_app(
            settings, broker_factory=lambda dsn: self.broker
        )

    async def test_pinned_tls_leaf_reaches_broker_with_registry_identity(self):
        status, body = await self._request(self.app, tls={
            "spec_version": "0.3",
            "client_cert_chain": [self.pem.decode("ascii")],
        })
        self.assertEqual(status, 200, body.decode("utf-8"))
        payload = json.loads(body)
        self.assertEqual(payload["repository"], "owner/private-repo")
        self.assertEqual(len(self.broker.calls), 1)
        self.assertEqual(
            self.broker.calls[0],
            {
                "task_id": self.task_id,
                "principal_id": "worker.staging.asgi-test",
                "role": "worker",
                "lease_fence": 7,
                "verifier_claim_token": None,
            },
        )
        self.assertNotIn("principal_id", payload)
        self.assertNotIn("access_token", payload)

    async def test_missing_tls_extension_and_spoofed_header_fail_closed(self):
        status, body = await self._request(
            self.app,
            headers=[
                (b"content-type", b"application/json"),
                (b"x-client-cert", self.pem),
                (b"x-workload-principal", b"worker.staging.asgi-test"),
            ],
        )
        self.assertEqual(status, 401, body.decode("utf-8"))
        self.assertEqual(self.broker.calls, [])

    async def test_unpinned_client_certificate_fails_closed(self):
        unknown_pem, _, _ = _client_cert()
        status, body = await self._request(self.app, tls={
            "spec_version": "0.3",
            "client_cert_chain": [unknown_pem.decode("ascii")],
        })
        self.assertEqual(status, 401, body.decode("utf-8"))
        self.assertEqual(self.broker.calls, [])

    async def test_tls_verification_error_fails_before_broker_resolution(self):
        status, body = await self._request(self.app, tls={
            "spec_version": "0.2",
            "client_cert_error": "certificate verify failed",
            "client_cert_chain": [self.pem.decode("ascii")],
        })
        self.assertEqual(status, 401, body.decode("utf-8"))
        self.assertEqual(self.broker.calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
