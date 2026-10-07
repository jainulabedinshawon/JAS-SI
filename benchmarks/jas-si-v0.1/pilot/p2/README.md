# JAS-SI Pilot P2 — Oracle Adversarial Control

## Purpose

P2 validates the integrity of the P1 oracle/ground-truth
verification apparatus under controlled adversarial outcome/report
mismatches.

P2 is an apparatus-validation stage.

It is NOT a measurement of JAS-SI intelligence performance.

---

## Research Question

Can the verification apparatus correctly classify controlled
adversarial mismatches without treating the agent's self-reported
success state as evidence of actual success?

---

## P2 Boundary

P2 tests:

1. Correct observation + SUCCESS report.
2. Wrong observation + SUCCESS report.
3. Wrong observation + FAILURE report.
4. Correct observation + FAILURE report.
5. Contradictory reports for the same wrong observation.

The verifier must derive verification from:

    expected_outcome
        +
    observed_outcome

and must not use the agent's reported outcome as evidence that
the observed outcome actually matched the expected outcome.

---

## Controls

### P2-A

Expected: EXPECTED
Observed: EXPECTED
Report: SUCCESS

Expected classification:

    TRUE_SUCCESS

### P2-B

Expected: EXPECTED
Observed: WRONG
Report: SUCCESS

Expected classification:

    FALSE_SUCCESS

This is the primary false-success adversarial control.

### P2-C

Expected: EXPECTED
Observed: WRONG
Report: FAILURE

Expected classification:

    FAILURE

### P2-D

Expected: EXPECTED
Observed: EXPECTED
Report: FAILURE

Expected classification:

    TRUE_SUCCESS

This tests that an incorrect failure report cannot override
evidence of actual success.

### P2-E

The same wrong observation is tested with contradictory reports.

The verifier must not turn either case into TRUE_SUCCESS.

---

## Pass Criterion

All predefined adversarial cases must:

- match the expected outcome label;
- match the expected verification state;
- match the exact-match state;
- declare verification independent of the agent report;
- pass the paired contradictory-report control where defined.

Required result:

    all_cases_passed = true
    pass_rate = 1.0

---

## Interpretation

A P2 PASS establishes only that the current P1 verifier behaves
correctly on the predefined adversarial controls.

It does NOT establish:

- JAS-SI intelligence superiority;
- real-world reliability;
- general adversarial robustness;
- benchmark superiority;
- novelty;
- production safety;
- resistance to unknown attacks.

---

## Stop Rule

If any P2 control fails:

1. Stop pilot progression.
2. Do not proceed to P3-P10.
3. Diagnose the apparatus.
4. Correct only the permitted apparatus defect.
5. Re-run P1 if the correction changes P1 behavior.
6. Re-run P2.
7. Record the correction before continuing.

---

## Independence Boundary

The P2 test reuses the P1 IndependentVerifier.

P2 does not create a second verifier implementation for comparison.

This prevents a test oracle from being replaced by another
independently unvalidated implementation.

---

## Expected Result

P2 is expected to pass with the current P1 verifier because
verification is based on:

    observed_outcome == expected_outcome

rather than:

    reported_status == SUCCESS
