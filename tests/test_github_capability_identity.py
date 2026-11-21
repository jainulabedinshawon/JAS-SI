"""Adversarial tests for pinned GitHub capability workload identities."""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.github_capability_identity import (
    CertificateWorkloadIdentityRegistry,
    WorkloadIdentity,
    WorkloadIdentityError,
    require_authenticated_workload,
)


class CertificateWorkloadIdentityTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.der = self._certificate(
            self.private_key,
            not_before=self.now - timedelta(minutes=5),
            not_after=self.now + timedelta(hours=1),
        )
        cert = x509.load_der_x509_certificate(self.der)
        self.fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        self.identity = WorkloadIdentity("worker.staging.instance-1", "worker")
        self.registry = CertificateWorkloadIdentityRegistry(
            {self.fingerprint: self.identity}
        )

    def _certificate(self, key, *, not_before, not_after, client_auth=True):
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "jas-si-test-workload")
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before.replace(tzinfo=None))
            .not_valid_after(not_after.replace(tzinfo=None))
        )
        if client_auth:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
        certificate = builder.sign(key, hashes.SHA256())
        return certificate.public_bytes(serialization.Encoding.DER)

    def test_resolves_exact_pinned_worker_certificate(self):
        self.assertEqual(
            self.registry.resolve(self.der, now=self.now),
            self.identity,
        )

    def test_unknown_certificate_is_rejected_even_if_client_auth_valid(self):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_der = self._certificate(
            other_key,
            not_before=self.now - timedelta(minutes=5),
            not_after=self.now + timedelta(hours=1),
        )
        with self.assertRaisesRegex(WorkloadIdentityError, "not registered"):
            self.registry.resolve(other_der, now=self.now)

    def test_expired_and_not_yet_valid_certificates_are_rejected(self):
        expired = self._certificate(
            self.private_key,
            not_before=self.now - timedelta(hours=2),
            not_after=self.now - timedelta(seconds=1),
        )
        future = self._certificate(
            self.private_key,
            not_before=self.now + timedelta(seconds=1),
            not_after=self.now + timedelta(hours=1),
        )
        for der in (expired, future):
            with self.assertRaises(WorkloadIdentityError):
                self.registry.resolve(der, now=self.now)

    def test_certificate_without_client_auth_usage_is_rejected(self):
        no_client_auth = self._certificate(
            self.private_key,
            not_before=self.now - timedelta(minutes=5),
            not_after=self.now + timedelta(hours=1),
            client_auth=False,
        )
        with self.assertRaisesRegex(WorkloadIdentityError, "client-auth"):
            self.registry.resolve(no_client_auth, now=self.now)

    def test_malformed_and_oversized_certificate_are_rejected(self):
        for value in (b"not-a-certificate", b"x" * 16_385, b""):
            with self.assertRaises(WorkloadIdentityError):
                self.registry.resolve(value, now=self.now)

    def test_workload_principal_cannot_exceed_postgresql_name_limit(self):
        with self.assertRaises(ValueError):
            WorkloadIdentity("w" * 63, "worker")

    def test_registry_rejects_invalid_fingerprint_role_and_duplicate_principal(self):
        with self.assertRaises(ValueError):
            CertificateWorkloadIdentityRegistry({"not-a-fingerprint": self.identity})
        with self.assertRaises(ValueError):
            WorkloadIdentity("verifier-1", "admin")
        with self.assertRaises(ValueError):
            CertificateWorkloadIdentityRegistry({
                "a" * 64: self.identity,
                "b" * 64: WorkloadIdentity("worker.staging.instance-1", "verifier"),
            })

    def test_fastapi_dependency_uses_only_tls_attached_certificate(self):
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(
                github_capability_identity_registry=self.registry
            )),
            state=SimpleNamespace(verified_client_certificate_der=self.der),
        )
        with patch(
            "jas_si_agent.github_capability_identity.datetime"
        ) as mocked_datetime:
            mocked_datetime.now.return_value = self.now
            self.assertEqual(require_authenticated_workload(request), self.identity)

    def test_missing_certificate_is_rejected_without_header_fallback(self):
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(
                github_capability_identity_registry=self.registry
            )),
            state=SimpleNamespace(),
            headers={"X-Workload-Identity": "worker.staging.instance-1"},
        )
        with self.assertRaises(HTTPException) as raised:
            require_authenticated_workload(request)
        self.assertEqual(raised.exception.status_code, 401)

    def test_unconfigured_registry_fails_closed(self):
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace()),
            state=SimpleNamespace(verified_client_certificate_der=self.der),
        )
        with self.assertRaises(HTTPException) as raised:
            require_authenticated_workload(request)
        self.assertEqual(raised.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main(verbosity=2)
