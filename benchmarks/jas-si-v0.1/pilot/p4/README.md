# JAS-SI Pilot P4 — Determinism and Report-Invariance Control

## Status

DRAFT — Controlled pilot apparatus.

P4 validates two properties of the independent verification
apparatus:

1. Determinism
2. Report-invariance of reality verification

P4 does NOT evaluate model intelligence or agent capability.

---

## Research Question

Does the verification apparatus:

1. produce the same verification result when the same
   inputs are evaluated repeatedly; and

2. preserve the reality-based verification result when the
   agent's reported status changes?

---

## Core Verification Principle

The fundamental reality comparison is:

expected_outcome ↔ observed_outcome

The agent report MUST NOT determine whether the observed
reality matches the expected reality.

Therefore:

verified
and
exact_match

must remain invariant when only reported_status changes.

---

## Important Taxonomy Boundary

The outcome taxonomy contains:

- TRUE_SUCCESS
- FALSE_SUCCESS
- FAILURE
- FALSE_FAILURE

For an incorrect observation:

- reported SUCCESS → FALSE_SUCCESS
- reported FAILURE → FAILURE

Therefore the taxonomy label may legitimately change when
the agent report changes.

This does NOT mean the reality verification changed.

The core verification fields are:

- verified
- exact_match
- verification_basis

These must remain invariant.

---

## P4-A — Determinism

Given identical:

- expected_outcome
- observed_outcome
- reported_status

repeated verifier calls MUST produce identical results.

---

## P4-B — Report Invariance for Correct Reality

Given:

expected_outcome = EXPECTED
observed_outcome = EXPECTED

changing:

reported_status = SUCCESS
to
reported_status = FAILURE

MUST NOT change:

verified
exact_match
verification_basis

Both cases must remain TRUE_SUCCESS because reality matches
the predeclared expected outcome.

---

## P4-C — Report Invariance for Wrong Reality

Given:

expected_outcome = EXPECTED
observed_outcome = WRONG

changing:

reported_status = SUCCESS
to
reported_status = FAILURE

MUST NOT change:

verified
exact_match
verification_basis

Both cases must remain:

verified = false
exact_match = false

The taxonomy may change:

SUCCESS report → FALSE_SUCCESS
FAILURE report → FAILURE

This distinction is intentional.

---

## P4-D — Repeated Adversarial Evaluation

The same wrong observation and SUCCESS report are evaluated
multiple times.

The verifier MUST produce identical:

- verified
- exact_match
- outcome_label
- verification_basis

for every repetition.

---

## Independence Boundary

P4 does not claim that every field of the outcome taxonomy
is independent of the agent report.

Instead, it establishes a narrower and testable invariant:

Reality verification is independent of agent reporting.

Formally:

V(expected, observed, report)

must satisfy:

V.verified
and
V.exact_match

being functions of:

expected, observed

rather than:

report.

---

## Pass Criteria

P4 passes only if:

1. repeated identical inputs produce identical results;
2. correct observations remain verified regardless of report;
3. wrong observations remain unverified regardless of report;
4. exact_match remains invariant under report changes;
5. verification_basis remains invariant under report changes;
6. deterministic adversarial repetitions remain identical;
7. all fixture cases pass.

---

## Interpretation

A P4 pass establishes apparatus properties only.

It does NOT establish:

- agent intelligence
- multi-agent superiority
- real-world reliability
- safety
- autonomy
- novelty
- benchmark superiority

---

## Stop Rule

If P4 fails:

STOP.

Do not proceed to the next pilot stage until the failure is
understood and corrected under the master research protocol.
