# JAS-SI Broker deployment topology decision (Staging gate)

Date: 2026-11-23
Scope: architecture decision and read-only infrastructure reconciliation; no service provisioning.

## Verified live platform state

- Render workspace service inventory currently returns zero services.
- The existing `render.yaml` defines three background workers: Agent Worker, Agent Verifier, and GitHub Installation Reconciler. It does not define a network-receiving Broker service.
- Neon Staging and Production branches are Ready but report `protected=false`. The Broker's dedicated LOGIN role is not yet provisioned; the existing capability role is a NOLOGIN boundary.
- The current Broker application is isolated from the public API, but the repository Dockerfile default still launches `jas_si_agent.api:app`. A service-specific start command is therefore mandatory.
- CI passes for PR #110's previous HEAD, but CI does not constitute a deployed Broker listener or mTLS proof.

## Deployment topology decision

The Broker must be a **Render private service** (Blueprint service type `pserv`), not a background worker: a worker cannot receive private-network requests. It must not be a public Render web service or the Vercel API process.

Render's public web-service load balancer terminates inbound TLS before forwarding HTTP. That topology cannot satisfy JAS-SI's present trust contract, which requires the actual TLS peer certificate in the ASGI TLS extension. The private service must terminate workload mTLS itself, using a server implementation proven to expose that extension (Anycorn is only a candidate, not yet an adopted dependency).

The Worker and Verifier may call the Broker over Render's same-region private network, but private-network reachability is not authentication. The Broker must still require a client certificate and bind it to the pinned workload registry; database authorization must bind the certificate principal to the task's current lease/claim.

## Required pre-deployment work (fail closed)

1. Select and review the TLS ASGI server; pin a complete hash-locked dependency set and inspect release/source provenance.
2. Add a dedicated Broker startup command and a private-service Blueprint entry, with no public ingress.
3. Implement secure certificate/key/CA provisioning and rotation without logging or committing material; verify TLS 1.2+, CERT_REQUIRED, trust-chain and expiry/revocation behavior.
4. Run a real-socket test against the **actual Broker ASGI app** behind the selected server: valid pinned workload accepted; no cert rejected at handshake; untrusted, expired, revoked, wrong-role, and spoofed-header cases rejected.
5. Provision the Staging-only Broker LOGIN role through a reviewed operation; verify session_user, NOINHERIT and narrow SET ROLE grants, and sslmode=verify-full.
6. Start Staging services only after cost/plan is confirmed; then prove private DNS, readiness, task-scoped DB authorization, persisted audit evidence, and independent verifier results.
7. Keep Production disabled and read-only until all Staging gates and rollback evidence pass.

## Completion semantics

This decision is **DESIGN VERIFIED**, not IMPLEMENTED, DEPLOYED, STAGING VERIFIED, or COMPLETE. No Render service, Neon role, deployment, credential, or paid resource was created or changed by this review.

Evidence references:
- Render private service vs worker distinction: https://render.com/docs/private-services
- Render Blueprint service type `pserv`: https://render.com/docs/blueprint-spec
- Render public web TLS termination: https://render.com/docs/web-services
- ASGI TLS extension contract: https://asgi.readthedocs.io/en/latest/specs/tls.html
- ASGI server support listing (Anycorn supports TLS extension; beta): https://asgi.readthedocs.io/en/latest/implementations.html
