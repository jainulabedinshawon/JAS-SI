"""Trusted ASGI TLS client-certificate transport for capability identity.

The ASGI TLS extension is the only accepted source. HTTP headers, cookies,
query parameters, and request bodies are never treated as peer certificates.

The TLS listener must require and validate client certificates (CERT_REQUIRED)
using a dedicated JAS-SI workload CA. This middleware does not perform PKI
chain validation; it transports the TLS listener's peer certificate to the
application, where exact SHA-256 pinning is performed. Deployments behind
TLS-terminating proxies that cannot provide the ASGI TLS extension must not
expose capability routes.
"""
from __future__ import annotations

from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


_STATE_KEY = "verified_client_certificate_der"
_MAX_CHAIN_LENGTH = 8
_MAX_PEM_BYTES = 32_768
_MAX_DER_BYTES = 16_384
_SUPPORTED_SPEC_VERSIONS = frozenset({"0.2", "0.3"})


def _client_certificate_der(scope: dict[str, Any]) -> bytes | None:
    """Return the TLS peer leaf certificate, or None when not authenticated."""
    extensions = scope.get("extensions")
    if not isinstance(extensions, dict):
        return None
    tls = extensions.get("tls")
    if not isinstance(tls, dict):
        return None

    spec_version = tls.get("spec_version", "0.2")
    if not isinstance(spec_version, str) or spec_version not in _SUPPORTED_SPEC_VERSIONS:
        return None

    # ASGI TLS 0.2 reports failed peer verification explicitly. Version 0.3
    # removes this field; deployments must use TLS CERT_REQUIRED.
    verification_error = tls.get("client_cert_error")
    if verification_error not in (None, ""):
        return None

    chain = tls.get("client_cert_chain", ())
    if isinstance(chain, (str, bytes)):
        return None
    try:
        certificates = tuple(chain)
    except TypeError:
        return None
    if not certificates or len(certificates) > _MAX_CHAIN_LENGTH:
        return None

    leaf_pem = certificates[0]
    if not isinstance(leaf_pem, str):
        return None
    try:
        encoded = leaf_pem.encode("ascii")
    except UnicodeEncodeError:
        return None
    if not encoded or len(encoded) > _MAX_PEM_BYTES:
        return None
    if b"-----BEGIN CERTIFICATE-----" not in encoded:
        return None

    try:
        leaf = x509.load_pem_x509_certificate(encoded)
        der = leaf.public_bytes(Encoding.DER)
    except (TypeError, ValueError):
        return None
    if not der or len(der) > _MAX_DER_BYTES:
        return None
    return der


class ASGITLSClientCertificateMiddleware:
    """Expose only the TLS extension's leaf certificate in request.state."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        child_scope = dict(scope)
        current_state = scope.get("state")
        child_state = dict(current_state) if isinstance(current_state, dict) else {}
        # Never preserve a caller/upstream-supplied value for this reserved key.
        child_state.pop(_STATE_KEY, None)
        certificate_der = _client_certificate_der(scope)
        if certificate_der is not None:
            child_state[_STATE_KEY] = certificate_der
        child_scope["state"] = child_state
        await self.app(child_scope, receive, send)
