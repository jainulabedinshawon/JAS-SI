# JAS-SI Pilot P1 — Oracle Apparatus

Status: Development / Prerequisite Validation

This package implements the P0 Pilot Harness and the P1 Oracle Agent
apparatus for JAS-SI.

## Purpose

P1 does NOT evaluate JAS-SI performance.

P1 validates the measurement apparatus itself:

Ground Truth
→ Expected Outcome
→ Observed Outcome
→ Verification
→ Outcome Label
→ Metric

The apparatus must be able to reproduce this chain deterministically
before later pilot conditions are evaluated.

## Scope

P1 currently validates:

- deterministic task loading
- deterministic oracle execution
- independent outcome verification
- TRUE_SUCCESS classification
- FALSE_SUCCESS classification
- evidence record generation
- aggregate result generation
- schema structure
- reproducibility of outcome labels

## Non-Claims

Passing P1 does not establish:

- JAS-SI superiority
- novelty
- independent verification performance
- corrigibility performance
- verified-failure learning
- real-world reliability
- benchmark superiority

Those claims require later controlled evaluation.

## Runtime

Required Python version:

Python 3.10

The P1 workflow intentionally uses only the Python standard library.
No third-party runtime dependency is required.

## Main Components

### schemas/

Machine-readable JSON schemas defining:

- pilot task
- pilot evidence
- pilot run

### fixtures/

Predeclared P1 tasks and expected outcomes.

### agents/

Deterministic Oracle Agent used only to validate the apparatus.

### verifier/

Independent verifier that derives the verified outcome from the
predeclared ground truth and observed outcome.

### harness/

Execution harness connecting the agent and verifier.

### run_p1.py

Runs the complete P1 apparatus and writes:

results/p1_oracle_result.json

### tests/

Unit tests for the P1 apparatus.

## P1 Gate

P1 passes only if:

1. all fixture tasks execute successfully;
2. expected outcomes are preserved;
3. observed outcomes match ground truth;
4. verifier labels successful runs as TRUE_SUCCESS;
5. verifier detects a simulated false-success case;
6. evidence records are structurally valid;
7. aggregate counts are correct;
8. repeated deterministic execution produces identical outcome labels;
9. result artifact is generated successfully.

A failure of any gate must cause the GitHub Actions workflow to fail.

## Reproducibility

Runtime timestamps may differ between executions.

The following P1 outputs must remain deterministic:

- task ordering
- expected outcome
- observed outcome
- outcome label
- aggregate outcome counts
- accuracy
- task count
