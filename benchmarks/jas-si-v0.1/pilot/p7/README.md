# JAS-SI Pilot P7 — Leakage Check

## Status

DRAFT — Controlled development apparatus.

## Purpose

P7 checks whether agent-visible input contains structurally
identifiable oracle-only or ground-truth fields.

The apparatus scans nested JSON objects and arrays for
predeclared forbidden field names.

## Threat Model

The test assumes that the experiment designer has explicitly
declared fields that must remain hidden from the agent.

Examples include:

- ground_truth
- expected_outcome
- oracle_label
- reference_answer

The forbidden-key list is part of the test configuration.

## Pass Criterion

P7 passes when it:

1. accepts payloads without forbidden fields;
2. detects forbidden fields at nested levels;
3. detects forbidden fields inside arrays;
4. rejects malformed fixtures;
5. produces a reproducible JSON result;
6. correctly handles both positive and negative controls.

## Important Boundary

P7 performs structural key-name detection only.

It does not reliably detect:

- semantic leakage in ordinary text;
- paraphrased or encoded answers;
- information disclosed through external tools;
- leakage through model memory or hidden prompts;
- all possible forms of experimental contamination.

A clean P7 result is not proof that an experiment is leakage-free.

## Fixture Boundary

The development fixture contains clean and deliberately contaminated
payloads. These are apparatus tests, not observations of a real agent.

## Result

The runner writes:

benchmarks/jas-si-v0.1/results/p7_leakage_check_result.json

## Non-Claims

A P7 pass does not establish intelligence, safety, real-world
reliability, benchmark validity, or absence of all information leakage.
