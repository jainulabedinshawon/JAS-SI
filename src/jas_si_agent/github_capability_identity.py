"""Pinned X.509 client-certificate identities for the GitHub capability broker.

The TLS terminator must validate the client certificate chain and attach the
peer leaf certificate DER to request.state.verified_client_certificate_der.
This module deliberately does not accept identity from HTTP headers, request
JSON, task UUIDs, or caller-provided principal names.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID
from fastapi import HTTPException, Request


_PRINCIPAL_RE = re.compile(r"^[a-z][a-z0-9._:-]{2,62}$")
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_ROLES = frozenset({"worker", "verifier"})


class WorkloadIdentityError(ValueError):
    """A peer certificate cannot be mapped to an authorized workload."""


@dataclass(frozen=True)
class WorkloadIdentity:
    """Server-side identity assigned to a pinned client certificate."""

    principal_id: str
    role: str

    def __post_init__(self) -> None:
        if not isinstance(self.principal_id, str) or not _PRINCIPAL_RE.fullmatch(
            self.principal_id
        ):
            raise ValueError("workload principal ID is invalid")
        if self.role not in _ALLOWED_ROLES:
            raise ValueError("workload role must be worker or verifier")


class CertificateWorkloadIdentityRegistry:
    """Resolve TLS-verified leaf certificates through an exact SHA-256 pin map.

    Certificate-chain validation is the responsibility of the TLS listener.
    Exact leaf-certificate pinning here prevents a different valid client
    certificate from inheriting a workload identity.
    """

    def __init__(self, identities: Mapping[str, WorkloadIdentity]) -> None:
        if not isinstance(identities, Mapping) or not identities:
            raise ValueError("at least one pinned workload certificate is required")
        normalized: dict[str, WorkloadIdentity] = {}
        principals: set[str] = set()
        for fingerprint, identity in identities.items():
            if (
                not isinstance(fingerprint, str)
                or not _FINGERPRINT_RE.fullmatch(fingerprint)
                or not isinstance(identity, WorkloadIdentity)
                or fingerprint in normalized
                or identity.principal_id in principals
            ):
                raise ValueError("workload certificate identity map is invalid")
            normalized[fingerprint] = identity
            principals.add(identity.principal_id)
        self._identities = normalized

    def resolve(
        self, certificate_der: bytes, *, now: datetime | None = None
    ) -> WorkloadIdentity:
        """Resolve a currently valid, client-auth-enabled, exactly pinned cert."""
        if (
            not isinstance(certificate_der, bytes)
            or not certificate_der
            or len(certificate_der) > 16_384
        ):
            raise WorkloadIdentityError("client certificate is missing or invalid")
        try:
            certificate = x509.load_der_x509_certificate(certificate_der)
        except (TypeError, ValueError):
            raise WorkloadIdentityError("client certificate is invalid") from None

        instant = now or datetime.now(timezone.utc)
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("certificate validation time must be timezone-aware")
        instant = instant.astimezone(timezone.utc)
        not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
        if instant < not_before or instant > not_after:
            raise WorkloadIdentityError("client certificate is outside its validity period")

        try:
            eku = certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
        except x509.ExtensionNotFound:
            raise WorkloadIdentityError("client certificate lacks client-auth usage") from None
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
            raise WorkloadIdentityError("client certificate is not valid for client authentication")

        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        identity = self._identities.get(fingerprint)
        if identity is None:
            raise WorkloadIdentityError("client certificate is not registered")
        return identity


def require_authenticated_workload(request: Request) -> WorkloadIdentity:
    """FastAPI dependency; trusts only certificate bytes attached by TLS ingress."""
    registry = getattr(request.app.state, "github_capability_identity_registry", None)
    if not isinstance(registry, CertificateWorkloadIdentityRegistry):
        raise HTTPException(
            status_code=503,
            detail="Capability workload identity registry is not configured",
        )
    certificate_der = getattr(
        request.state, "verified_client_certificate_der", None
    )
    if not isinstance(certificate_der, bytes):
        raise HTTPException(status_code=401, detail="Authenticated workload certificate required")
    try:
        return registry.resolve(certificate_der)
    except WorkloadIdentityError:
        raise HTTPException(status_code=401, detail="Workload identity is not authorized") from None
