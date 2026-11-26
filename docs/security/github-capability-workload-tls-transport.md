# JAS-SI capability workload TLS transport

## Trust boundary

Capability workload identity is derived only from the peer certificate reported
by the ASGI TLS extension. The first PEM certificate is converted to DER and
passed to the existing SHA-256 pin registry. HTTP headers, cookies, query
parameters, task IDs, and JSON fields are never identity sources.

The ASGI TLS extension reports transport information; it is not a substitute
for configuring the TLS listener. A capability service must:

1. terminate TLS in the ASGI server itself (not an untrusted proxy);
2. require client certificates (CERT_REQUIRED) from a dedicated JAS-SI
   workload CA;
3. reject failed or absent client-certificate handshakes before application
   dispatch; and
4. pin the leaf certificate fingerprint to one workload principal and role.

The ASGI TLS extension exposes client_cert_error, which the adapter rejects
when non-empty. Deployments must still enforce verification at the TLS listener
with CERT_REQUIRED; the adapter deliberately supplies no identity when TLS is
terminated upstream and the ASGI server does not expose the TLS extension. Do
not copy a client certificate into an HTTP header to work around this limitation.

## Current deployment boundary

The Vercel-hosted public API is not evidence of mTLS workload transport. The
adapter is mounted in the FastAPI application but a request without the ASGI
TLS extension has no workload identity. The capability dependency remains
fail-closed until a dedicated ASGI service and verified mTLS listener are
provisioned. No Vercel, Render, Neon, or Cloudflare infrastructure is changed
by this code.

## Specification

ASGI TLS extension specification:
https://asgi.readthedocs.io/en/latest/specs/tls.html
