# GitHub Capability Broker Runtime — v1 boundary

## Purpose

This change adds an opt-in, metadata-only capability-resolution endpoint. It connects the pinned mTLS workload identity registry to the task-scoped PostgreSQL authorization routine introduced by PR #108.

It does NOT issue GitHub tokens, perform repository reads, execute agent actions, or claim private-repository runtime readiness.

## Request path

1. A dedicated trusted ASGI TLS listener requires client certificates and validates the certificate chain against the JAS-SI workload CA (CERT_REQUIRED).
2. The ASGI TLS extension supplies the peer leaf certificate. The existing middleware discards any certificate value that was not sourced from the TLS extension.
3. The pinned SHA-256 registry maps that certificate to a server-controlled principal_id and worker / verifier role.
4. The endpoint accepts only a task UUID plus the role-specific proof: a Worker lease fence or Verifier claim token. Extra request fields (including caller-supplied principal or role) are rejected.
5. A dedicated Broker database login connects with TLS hostname verification. Before SET ROLE, the adapter checks `session_user` is exactly `jas_si_agent_broker_login`; any other identity is rejected. It then executes SET ROLE jas_si_agent_capability_broker and calls jas_si_github_task_capability_resolve.
6. The database routine independently checks the active tenant, verified installation and repository binding, task type, persisted workload principal, lease/claim ownership, expiry, and Worker fence or Verifier claim token.
7. The endpoint returns authorized metadata only. No GitHub token or private key is returned.

## Required isolated deployment configuration

The endpoint is disabled by default. For a dedicated non-production Broker service only:

- Set JAS_SI_ENVIRONMENT=preview.
- Set JAS_SI_GITHUB_CAPABILITY_BROKER_ENABLED=true.
- Set JAS_SI_GITHUB_CAPABILITY_BROKER_DATABASE_URL to a dedicated Broker LOGIN DSN with sslmode=verify-full.
- Set JAS_SI_GITHUB_CAPABILITY_WORKLOAD_IDENTITIES to the exact SHA-256 fingerprint registry.
- Terminate mTLS at a trusted ASGI listener configured with a dedicated workload CA and mandatory client certificate validation. The TLS listener—not an HTTP proxy header—must supply the ASGI TLS extension.

Do not set these variables on the public Vercel deployment. The endpoint returns 404 unless explicitly enabled with JAS_SI_ENVIRONMENT=preview; development, test, and production environments are all denied. A configured fingerprint registry alone does not enable the endpoint.

The Broker DSN must authenticate as a dedicated jas_si_agent_broker_login role. That login must be NOINHERIT, have no superuser/role-creation/database-creation/replication/BYPASSRLS privileges, and have membership in jas_si_agent_capability_broker with INHERIT FALSE, SET TRUE, and ADMIN FALSE. PR #108 intentionally does not create login roles or credentials; provision this principal only through a separately reviewed Staging-only operations procedure.

## Cloudflare mTLS edge is not a drop-in ASGI TLS listener

Cloudflare Workers expose verified client-certificate state through request.cf.tlsClientAuth, and can forward RFC 9440 Client-Cert headers. Cloudflare documentation explicitly warns that certificate values may be present even for invalid certificates and that inbound Client-Cert / Client-Cert-Chain headers must be removed before trusted values are constructed.

The current JAS-SI ASGI middleware trusts the TLS extension, not forwarded HTTP certificate headers. Therefore a Cloudflare Worker forwarding certificate headers does NOT satisfy the current listener contract and must not be enabled as-is.

A future Cloudflare edge design requires a separately reviewed trust adapter: enforce certVerified=true, certRevoked=false, and complete/non-truncated certificate data at the edge; remove all client-supplied certificate/assertion headers; authenticate the Worker-to-origin channel so direct-origin requests cannot forge edge assertions; and use a replay-resistant, integrity-protected origin assertion or a real origin mTLS termination that provides the ASGI TLS extension. The origin must independently validate the assertion/certificate and bind it to the configured workload identity registry. Until implemented and adversarially tested, use a dedicated ASGI mTLS listener only.

The Cloudflare account inventory was read-only checked during this review and returned no deployed Workers scripts. The Access applications and mTLS certificate inventory APIs returned `access.api.error.not_enabled`; Cloudflare Access is not enabled on this account. No Worker, hostname, certificate, DNS, or origin settings were created or changed.

Cloudflare's current Access mTLS documentation states that Access mTLS is not included in its Free plan and requires Enterprise or pay-as-you-go Zero Trust. Free customers can use Access service tokens for automated authentication, but that is a different trust mechanism and is not a drop-in replacement for the existing certificate-fingerprint registry. Zone-level mTLS is a separate feature with separate plan availability and has not been validated for this account. Do not enable or purchase a plan as part of this PR.

## Important capability limitation

GitHub App installation tokens are repository-scoped, not path- or commit-scoped. This endpoint therefore does not hand a token to Worker or Verifier. If path-level and pinned-commit enforcement is required, the next stage must be a Broker-mediated read proxy that validates every requested path and commit against this persisted capability before making GitHub API calls. A raw repository token must not be described as enforcing path-level scope.

## Verified CI evidence for the Broker-login hardening code

Code revision tested: `ab3575f7d2505e6d7ac01957d85cb597d530d503`.

- GitHub Actions run 44957609315, "JAS-SI Agent Authorization Tests": PASS.
- GitHub Actions run 44957609337, "JAS-SI Dependency Lock Verification": PASS.
- GitHub Actions run 44957604746, "JAS-SI Vercel Python 3.12 Compatibility": PASS.
- GitHub Actions run 44957604729, "JAS-SI Post-Merge Security Verification": PASS.

The Broker adapter now checks the PostgreSQL `session_user` before entering the NOLOGIN capability role. Its unit tests reject a connection authenticated as `neondb_owner` before `SET ROLE`. The listed checks all completed successfully on the code revision above. Later documentation-only commits do not change that tested code revision.

These are CI checks, not deployment or end-to-end evidence.

## Evidence gates still outstanding

- Trusted mTLS listener deployment and certificate-chain configuration evidence.
- Dedicated Broker login provisioned on Neon Staging and its membership/ACL verified. The NOLOGIN capability role and task-scoped resolver exist, but the dedicated login does not.
- PR #108 task-scoped Broker migration has been applied to Neon Staging only; catalog checks confirm the role and resolver boundary. No Production migration has been run.
- Adversarial Staging E2E for Worker and Verifier, including cross-principal, stale fence, expired claim, wrong tenant/repository, and request-header/body spoofing.
- Broker-mediated repository-read proxy, token issuer composition, and independent verification of returned GitHub content.
- Production remains read-only; no production enablement is authorized by this change.


## ASGI TLS extension runtime compatibility gate (2026-11-22)

The middleware contract requires the TLS terminator to place the peer leaf PEM certificate in `scope["extensions"]["tls"]["client_cert_chain"]`. Do not assume that enabling HTTPS or mutual TLS on an arbitrary ASGI server satisfies this contract.

The official ASGI implementation list identifies Anycorn as an implementation supporting the TLS extension. Its upstream 0.20.1 source includes a real mutual-TLS end-to-end test that configures `ca_certs` and `verify_mode = ssl.CERT_REQUIRED`, makes a TLS client request with a client certificate, and asserts that the ASGI scope contains the presented client certificate chain. Anycorn is marked Beta and is maintained by a single maintainer in the current PyPI metadata; therefore it is a candidate to validate, not an automatically approved production dependency.

Runtime selection gate:
- Uvicorn or Hypercorn must NOT be used as the Broker TLS terminator unless an exact-version JAS-SI integration test proves the required TLS scope extension is present.
- Anycorn 0.20.1 is the current candidate because its upstream source contains the real mTLS/TLS-extension E2E test. Before adoption, pin its complete transitive dependency graph with hashes in a dedicated runtime lock, review the release provenance and source, and run JAS-SI-owned real-socket tests on Python 3.10.
- The JAS-SI-owned test must run the actual `create_github_capability_app` behind the candidate server with `CERT_REQUIRED`; assert a valid pinned certificate succeeds, missing certificate fails at TLS handshake, unknown/revoked/expired certificate is rejected, and caller-supplied identity headers are ignored.
- Test both direct TLS termination and the exact deployed listener topology. Any proxy/load balancer that strips the TLS extension is incompatible unless a separately reviewed authenticated trust adapter is implemented.
- Configure a dedicated workload CA, server certificate/key, TLS 1.2 minimum, `verify_mode=CERT_REQUIRED`, and no insecure bind. Keep the listener private and do not expose it through the public Vercel app.
- No Broker runtime is approved for deployment until these tests, dependency-lock verification, certificate rotation/revocation tests, and independent Staging E2E pass.

This compatibility review does not add Anycorn to the JAS-SI dependency set and does not create a runtime service. It records the verified server-selection constraint only.
