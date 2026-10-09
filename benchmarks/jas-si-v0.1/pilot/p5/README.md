# JAS-SI Pilot P5 — Floor/Ceiling Check

## Status

DRAFT — Controlled pilot apparatus.

## Purpose

P5 checks whether primary metrics discriminate between
experimental conditions or are uniformly saturated at 0%
or 100%.

P5 validates the floor/ceiling detection apparatus.
It does not establish JAS-SI performance or novelty.

## Primary Metrics

For each condition, calculate:

- FSR = FALSE_SUCCESS / (TRUE_SUCCESS + FALSE_SUCCESS)
- RA = (TRUE_SUCCESS + FAILURE) / total_runs
- FFR = FALSE_FAILURE / (FALSE_FAILURE + FAILURE)

All metric denominators must be positive.

## Exclusion Rule

Scripted control agents used in P1 and P2 are excluded
from the discriminative floor/ceiling criterion.

Their extreme results may be expected by design.

## Pass Criterion

Across the included discriminative conditions, each
primary metric must not be uniformly 0.0 or uniformly
1.0.

A metric uniformly equal to 0.0 or 1.0 indicates
saturation and triggers a floor/ceiling warning.

A saturated metric causes P5 to fail.

## Fixture Boundary

The committed fixture tests two things:

1. A discriminative example is accepted.
2. A saturated example is rejected.

These are apparatus controls, not actual agent results.

## Real Experimental Data

Before benchmark freeze, run P5 on actual Baseline A
and experimental-condition outcomes.

Do not substitute this development fixture for actual
experimental evidence.

## Stop Rule

If the apparatus fails or real discriminative conditions
show metric saturation, investigate and revise the
affected task or condition before benchmark freeze.

## Non-Claims

A P5 pass does not establish:

- intelligence;
- safety;
- real-world reliability;
- multi-agent superiority;
- novelty;
- benchmark superiority.
