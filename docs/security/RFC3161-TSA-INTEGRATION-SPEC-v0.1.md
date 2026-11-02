JAS-SI RFC 3161 Trusted Timestamp Integration Specification v0.1

Status: Finalized Specification — Implementation Baseline
Scope: RFC 3161 timestamp acquisition, cryptographic verification, certificate revocation assessment, evidence retention, and offline re-verification.
Parent project: JAS-SI Trusted Anchor / Independent Verification

---

1. Purpose

This specification defines how JAS-SI obtains, preserves, and independently verifies RFC 3161 timestamp tokens for security checkpoint digests.

A successfully verified timestamp token provides evidence that a particular message imprint existed no later than the time asserted by the Timestamp Authority (TSA), subject to the applicable cryptographic, certificate, trust, temporal, and policy checks.

A timestamp token does not independently prove that an arbitrary remote application action occurred. It does not establish that the TSA inspected or verified the underlying application event.

RFC 3161 integration is a separate integration track from the existing JSON Trusted Anchor API. RFC 3161 does not provide the JSON API's Bearer authentication, idempotency, lookup, or application-level receipt semantics.

The implementation must preserve this separation.

2. Cryptographic Requirements

- SHA-256 is the minimum accepted message-imprint algorithm.
- SHA-384 and SHA-512 may also be supported.
- SHA-1 and weaker algorithms must be rejected.
- The verifier must validate:
  - CMS signature integrity.
  - Signer identity.
  - Certificate path and trust basis.
  - Message-imprint algorithm and digest equality.
  - Request nonce equality when a nonce was requested.
  - TSA policy OID against an explicit allowlist.
  - TSA certificate Extended Key Usage.
  - Relevant certificate validity and critical-extension requirements.
- The TSA signing certificate must contain the "id-kp-timeStamping" Extended Key Usage.
- The timestamping EKU extension must be critical, and the certificate must be restricted to the timestamping purpose as required by RFC 3161.
- The implementation must use OpenSSL or a maintained cryptographic library. JAS-SI must not implement its own ASN.1 or CMS cryptographic parser.

A successful CMS signature check alone is insufficient to establish a valid timestamp.

3. Verification Stages

Stage A — RFC 3161 and CMS Verification

The verifier must check:

1. Timestamp response status.
2. CMS signature integrity and signer identity.
3. Certificate path against the configured trust store.
4. Message-imprint algorithm and digest equality.
5. Request nonce equality with the response nonce, when a nonce was requested.
6. TSA policy OID against the configured allowlist.
7. Certificate validity at the timestamp's asserted "genTime".
8. TSA certificate "id-kp-timeStamping" EKU and critical-extension requirements.
9. Timestamp generation time and available accuracy information.
10. Applicable certificate constraints and path-validation requirements.

By default, only an RFC 3161 response with an acceptable granted status should be accepted. A "grantedWithMods" response must be rejected unless the configured TSA profile explicitly permits it and the modifications are understood and validated.

3.1 Temporal certificate validation

Certificate path validity must be evaluated at the timestamp's asserted "genTime", not merely at the time of later verification.

The implementation must distinguish:

- "genTime": the time asserted by the TSA.
- Acquisition time: the local request and response-receipt times.
- Evaluation time: the time at which verification is performed.

These timestamps serve different purposes and must be recorded separately.

A certificate that expired after "genTime" must not automatically fail historical certificate-validity evaluation solely because it is expired at the later evaluation time.

However, historical validity does not bypass revocation, trust, policy, or other mandatory checks.

The implementation must explicitly establish that its certificate path validation is performed at "genTime". A successful "openssl ts -verify" invocation must not be assumed to prove that every required temporal and policy check has been performed.

OpenSSL command behavior and supported validation-time controls must be tested against the pinned OpenSSL version. Additional certificate-path validation may be necessary.

3.2 OpenSSL verification boundary

OpenSSL "ts -verify" may be used for RFC 3161 token verification, including relevant CMS, message-imprint, and trust checks.

Its successful result must not be interpreted as proof that:

- OCSP or CRL revocation assessment has completed.
- Every certificate in the intended path has passed the required historical validity checks.
- The TSA policy allowlist has been enforced.
- Acquisition-time clock tolerance has passed.
- The offline evidence bundle is complete.

These are separate JAS-SI verification responsibilities.

Stage B — Certificate Revocation Assessment

Revocation assessment is separate from Stage A and is mandatory before a timestamp can receive a final "VALID" result.

The assessment must cover every applicable non-trust-anchor certificate in the validated certificate path, including:

- TSA end-entity signing certificate.
- Intermediate CA certificates.

The trust anchor/root certificate is managed through the independently approved trust-store process. It is not treated as an ordinary certificate requiring routine OCSP/CRL validation.

Delegated OCSP responder certificates must also be validated for authorization, certificate path, validity, and applicable EKU requirements.

Supported revocation evidence includes:

- OCSP responses.
- CRLs.
- Required issuer and responder certificates.
- Relevant CRL distribution-point and OCSP responder information.

For every applicable certificate, the verifier must validate:

- Revocation evidence signature.
- Issuer relationship.
- Responder authorization, where applicable.
- Evidence validity interval.
- Relevant certificate and CRL extensions.
- Historical status at "genTime".

Possible per-certificate revocation outcomes:

- "GOOD"
- "REVOKED"
- "UNKNOWN"
- "UNAVAILABLE"

"UNKNOWN" and "UNAVAILABLE" must never be treated as "GOOD".

3.3 Revocation timing rules

Revocation status must be interpreted relative to "genTime", using the available revocation time and, where present, the "invalidityDate" extension.

The verifier must distinguish the time a revocation was published or recorded from the time the certificate is indicated to have become invalid.

The following rules apply:

1. If valid revocation evidence establishes that the certificate was not revoked at "genTime", the certificate may pass the revocation check.
2. If the certificate is revoked and the revocation time is unavailable, the result is "INDETERMINATE".
3. If the revocation time is at or before "genTime", the result is "INVALID".
4. If the revocation time is after "genTime", but an applicable "invalidityDate" is at or before "genTime", the result is "INVALID".
5. If the revocation reason is "keyCompromise" or "cACompromise", the revocation time is after "genTime", and no reliable "invalidityDate" is available, the result is "INDETERMINATE".
6. If the revocation time is after "genTime", the reason is explicitly non-compromise, and reliable evidence establishes that the certificate was valid at "genTime", historical revocation assessment may pass.
7. An unspecified or ambiguous revocation reason must produce "INDETERMINATE" unless sufficient independent evidence resolves the historical status.
8. "certificateHold" and "removeFromCRL" must be interpreted using the applicable CRL history and delta-CRL semantics. They must not be treated as ordinary permanent revocation or automatic restoration without sufficient evidence.
9. Unsupported or ambiguous revocation reasons, including authority- or attribute-authority compromise cases, must not be silently treated as harmless non-compromise revocations.

The implementation must use a documented reason-code interpretation policy. Unresolved historical status must fail closed.

3.4 Chain-level revocation result

The chain-level revocation outcome is determined by the least favorable applicable certificate result:

- Any "INVALID" certificate result makes the chain revocation result "INVALID".
- If no certificate is "INVALID", but at least one is "INDETERMINATE", the chain result is "INDETERMINATE".
- The chain passes only when every applicable non-trust-anchor certificate has a supported and acceptable historical revocation assessment.

A later revocation event must trigger a new assessment and alert downstream consumers.

It must not silently rewrite the original verification record. Reassessment results must be preserved as separate, linked records.

4. Trust Anchor Management

- Trust anchors must come from an independently approved and controlled source.
- Certificates returned by a TSA must never automatically become trusted roots.
- The trust store must be versioned.
- Root certificate fingerprints must be recorded.
- Trust-store updates must produce auditable change records.
- Offline verification must use the explicitly recorded trust-store version.
- Missing, modified, or unrecognized trust anchors must fail closed.
- Trust-anchor removal, distrust, or replacement must be handled through an explicit and auditable policy process.

The trust anchor is a configured trust decision, not merely another certificate supplied by the TSA.

5. TSA Policy and Time Accuracy

5.1 Policy OID

Each TSA profile must define an explicit allowlist of accepted TSA policy OIDs.

An empty allowlist means no TSA policy is approved. The verifier must not silently accept arbitrary policy OIDs.

An allowlist may be populated only after the selected TSA's published policy, certificate chain, and operational conditions have been reviewed.

The active allowlist and its version must be recorded in each verification record.

5.2 Clock tolerance — acquisition window only

Initial engineering acceptance threshold:

"genTime" must fall within:

"[request_time - tolerance, receive_time + tolerance]"

The default tolerance is 300 seconds.

This is an initial JAS-SI engineering policy, not an RFC 3161 requirement.

The tolerance must be measured against a separately monitored and synchronized local reference clock.

- Clock-tolerance enforcement applies only during initial acquisition.
- Offline and later re-verification must not compare "genTime" against the current wall clock.
- Later verification must rely on the preserved acquisition metadata and its integrity evidence.
- An unsynchronized or untrusted local clock must not be used to claim that the acquisition-time tolerance check passed.

The evidence record must include:

- Local request timestamp.
- Local response-receipt timestamp.
- Clock source identifier.
- Clock synchronization status.
- Configured tolerance.
- Token "genTime".
- TSA accuracy extension, if supplied.
- Acquisition metadata integrity reference.

A clock-tolerance failure must prevent a "VALID" result.

5.3 Acquisition metadata integrity

Acquisition metadata is not independently authenticated by the TSA token.

Therefore, JAS-SI must protect the integrity of:

- Request time.
- Response-receipt time.
- Clock source.
- Clock synchronization status.
- Configured tolerance.
- Acquisition verification result.

These values must be included in a versioned evidence manifest and protected by the JAS-SI audit-integrity mechanism.

Where available, the manifest digest should be anchored through an independently verifiable checkpoint.

If required acquisition metadata is missing, altered, or cannot be verified, the acquisition-time assessment must be "INDETERMINATE".

6. Verification Result and Fail-Closed Semantics

The final verifier must return exactly one of:

- "VALID"
- "INVALID"
- "INDETERMINATE"

"VALID"

All mandatory cryptographic, trust, policy, temporal, acquisition-time, and revocation requirements have passed.

"INVALID"

A mandatory integrity, signature, chain, imprint, nonce, EKU, policy, temporal, or revocation check has definitively failed.

"INDETERMINATE"

A mandatory check could not be completed, required evidence is missing or insufficient, or the result cannot be reliably established.

Downstream behavior:

- Only "VALID" may be considered for Trusted Anchor confirmation.
- "INVALID" must be rejected.
- "INDETERMINATE" must never set Trusted Anchor to "CONFIRMED".
- Retry or manual review may be initiated without changing the original result.
- A retry must create a new attempt record.
- No fallback may convert an unknown verification state into success.

A verification result must include the verifier version, trust-store version, TSA profile version, policy configuration version, and applicable revocation assessment references.

7. Retry and Multiple Token Semantics

RFC 3161 does not define an application-level idempotency guarantee.

Every timestamp request attempt must have its own record containing:

- Unique attempt identifier.
- Original request bytes.
- Request nonce, if used.
- Checkpoint digest.
- Request time.
- TSA endpoint.
- TSA profile version.
- Response status.
- Original response and token bytes, if received.
- Verification outcome.
- Relevant error or failure classification.

Multiple valid timestamp tokens may refer to the same checkpoint digest.

The data model must preserve every attempt and must never overwrite an earlier token with a later token.

A retry is a new attempt, not proof that the previous attempt returned the same token.

A request without a nonce must not claim nonce-based response binding.

8. Evidence Retention and Integrity

The initial implementation must provide:

1. Append-only evidence records.
2. Hash-chained audit records.
3. Original request and token byte preservation.
4. Versioned verifier configuration.
5. Versioned trust-store references.
6. TSA profile and policy configuration references.
7. Acquisition metadata preservation.
8. Exportable evidence bundles for independent offline verification.

A hash chain alone does not provide absolute immutability against an attacker capable of rewriting the entire store.

Production deployment should add WORM storage or an equivalent independently controlled retention mechanism.

Secrets, private keys, Bearer credentials, and unrelated sensitive operational data must not be included in exported evidence bundles.

9. Offline Re-verification

Offline re-verification is a separate acceptance gate.

An exported evidence bundle must contain sufficient material to repeat the required verification without network access.

The bundle must include:

- Original RFC 3161 request bytes.
- Original timestamp token bytes.
- Checkpoint digest and request nonce, if used.
- Full TSA certificate chain required for path validation.
- Required intermediate and responder certificates.
- Applicable OCSP evidence and/or CRLs for every applicable non-trust-anchor certificate.
- Revocation evidence fetch timestamps.
- Relevant OCSP and CRL metadata.
- Pinned trust anchor and trust-store version.
- TSA policy allowlist and version.
- TSA profile version.
- Recorded acquisition-time metadata.
- Clock source and synchronization evidence.
- Acquisition metadata integrity proof.
- Verifier version.
- OpenSSL version and relevant configuration.
- Original verification result and its configuration references.

Offline verification must not fetch missing certificates, trust anchors, OCSP responses, or CRLs from the network.

9.1 Revocation evidence freshness and historical sufficiency

Revocation evidence freshness and historical status sufficiency are separate assessments.

The implementation must record both:

- "freshness_at_fetch"
- "historical_status_sufficiency"

For OCSP evidence, preserve relevant fields including:

- "producedAt"
- "thisUpdate"
- "nextUpdate", when present
- "revocationTime", when present
- Responder identity and authorization evidence.

For CRL evidence, preserve relevant fields including:

- "thisUpdate"
- "nextUpdate", when present
- CRL number, when present
- Issuing distribution point information, where applicable.
- Delta-CRL and base-CRL relationships, where applicable.

Evidence is stale when:

- Its validity interval does not cover its recorded fetch time; or
- It violates the configured maximum-age policy when an explicit "nextUpdate" is absent.

The maximum-age policy must be explicit, versioned, and recorded.

The verifier must not use the current wall clock to retroactively determine whether evidence was fresh at its recorded fetch time.

Historical sufficiency is a separate question: the evidence must support a defensible determination of certificate status at "genTime".

Evidence that was fresh when fetched may still be insufficient to establish historical status. Conversely, evidence must not be rejected solely because it is old at the time of a later offline verification if its recorded validity and historical coverage remain adequate under the applicable policy.

If required evidence is missing, stale at fetch time, or insufficient to determine status at "genTime", the result must be "INDETERMINATE".

9.2 Offline verification restrictions

Offline verification must be performed in a network-disabled environment.

The verifier must:

- Use only evidence contained in the exported bundle and the explicitly recorded trust configuration.
- Reject missing or modified mandatory evidence.
- Avoid automatic certificate, OCSP, CRL, or trust-anchor retrieval.
- Record the offline verification result separately from the original result.
- Preserve both results and their configuration references.

Offline verification must not silently repair incomplete evidence by contacting external services.

10. Negative Test Requirements

The test suite must demonstrate rejection or indeterminate behavior for:

- Incorrect message imprint.
- Incorrect nonce.
- Tampered timestamp token.
- Invalid CMS signature.
- Untrusted certificate chain.
- Missing timestamping EKU.
- Non-critical timestamping EKU.
- Certificate not restricted to timestamping purpose.
- Unapproved policy OID.
- Weak hash algorithm.
- Certificate invalid at "genTime".
- Certificate revoked at or before "genTime".
- Certificate revoked after "genTime" with "keyCompromise" and an "invalidityDate" at or before "genTime".
- Certificate revoked after "genTime" with "keyCompromise" and no reliable "invalidityDate".
- Revoked certificate with no revocation time.
- Invalid or stale OCSP/CRL evidence.
- Missing revocation evidence for an applicable certificate in the chain.
- Invalid delegated OCSP responder authorization.
- Unsupported or ambiguous revocation reason.
- Incorrect "certificateHold" or "removeFromCRL" historical interpretation.
- Clock outside configured tolerance during acquisition.
- Unsynchronized acquisition clock.
- Missing or modified trust anchor.
- Missing or modified acquisition metadata.
- Incomplete offline evidence bundle.
- Offline verification attempting network access.
- Trust-store or policy-version mismatch.
- A "grantedWithMods" response when the active profile does not permit it.

Positive tests must include:

- A certificate that expired after "genTime" but was valid at "genTime".
- A certificate revoked after "genTime" for an explicitly non-compromise reason, with sufficient evidence establishing that it was valid at "genTime".
- A complete evidence bundle that successfully passes network-disabled offline re-verification.

Tests must distinguish "INVALID" from "INDETERMINATE".

11. TSA Provider Selection

A provider must not be approved solely because its endpoint responds.

Before integration, record:

- Endpoint and protocol compatibility.
- Published certificate chain and independent trust basis.
- Accepted hash algorithms.
- Accepted policy OIDs.
- Rate limits.
- Usage restrictions.
- Commercial-use terms.
- Availability and SLA claims, if any.
- Long-term availability and archival considerations.
- Operational and security contact information, where available.

A second independent TSA may be used for corroboration.

Independence must be evaluated using provider ownership, certificate issuance, trust infrastructure, and operational control relationships. Two endpoints alone do not establish independent corroboration.

Free public TSA services must not be treated as production-grade services without documented review.

Provider approval must be recorded separately from successful endpoint connectivity.

12. Acceptance Gates

The RFC 3161 integration is not complete until all applicable gates pass:

1. Real DNS/TCP/TLS connectivity to an approved TSA.
2. Successful RFC 3161 request and original token receipt.
3. Independent cryptographic token verification.
4. Certificate path validation evaluated at "genTime".
5. Trust-anchor pinning and policy allowlist enforcement.
6. Separate revocation validation for all applicable non-trust-anchor certificates.
7. Correct revocation timing and reason-code interpretation.
8. Clock-tolerance enforcement limited to the acquisition window.
9. Acquisition metadata integrity verification.
10. Negative tests for cryptographic, temporal, trust, and certificate failures.
11. Fail-closed downstream behavior.
12. Retry and multiple-token record preservation.
13. Append-only, hash-chained evidence retention.
14. Exportable evidence bundle.
15. Successful network-disabled offline re-verification.
16. Reproducible evidence bundle and verification report.

A mock response, local test double, or successful token download alone cannot satisfy the real-provider acceptance gates.

Each gate must be supported by retained test output or independently reviewable evidence.

13. Separation from Remote JSON API Integration

The existing JSON Trusted Anchor API remains a separate integration track.

Its real-provider acceptance gates include:

- Real HTTPS connection.
- Bearer authentication.
- Atomic idempotency.
- Conflicting-key rejection.
- Lookup consistency.
- Remote receipt verification.
- Remote concurrency behavior.

RFC 3161 success must not be used as evidence that these JSON API requirements have passed.

The two integration tracks may share approved evidence-storage and audit components, but their protocol-specific verification requirements must remain separate.

14. Current Implementation Status

This specification defines the implementation baseline. It does not claim that the implementation or any acceptance gate has been completed.

At the time of specification finalization:

- No real TSA integration is claimed complete.
- No production revocation validation is claimed complete.
- No network-disabled offline re-verification is claimed complete.
- No production TSA provider is approved by this document.
- No trust anchor or policy OID allowlist is implicitly approved.
- No production WORM retention mechanism is claimed complete.

Provider selection, trust-anchor approval, policy OID allowlisting, implementation, negative testing, evidence retention, and offline verification remain explicit prerequisites.

JAS-SI must report each acceptance gate as independently verified before claiming RFC 3161 Trusted Timestamp integration complete.
