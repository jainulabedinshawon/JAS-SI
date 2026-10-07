# JAS-SI Pilot P3 — Multi-Agent Reality Verification Control

## Status

DRAFT — Controlled pilot apparatus.

P3 is an apparatus-validation experiment.
It is NOT a claim that multi-agent systems are novel.

---

## Research Question

Can a more capable multi-agent/autopilot-style system operate
inside an independent verification boundary without allowing
agent self-report to define reality?

The experiment compares:

### Condition A — Single Agent

Agent
→ Action
→ Report
→ Independent Verification

### Condition B — Multi-Agent

Planner
→ Executor
→ Critic
→ Report
→ Independent Verification

The verification boundary remains unchanged.

---

## Core Invariant

The verified outcome MUST be derived from:

expected_outcome ↔ observed_outcome

and MUST NOT be derived from:

agent_report

Therefore:

Agent report ≠ ground truth.

---

## Conditions

### P3-A — Single Agent

A single simulated agent produces an action result and report.

### P3-B — Multi-Agent

A simulated planner creates an action plan,
an executor produces an observation,
and a critic produces a review.

The final agent report may be correct or incorrect.

The independent verifier remains outside the agent reporting chain.

---

## Controlled Variables

The following remain fixed between conditions:

- expected outcome
- observed outcome
- ground truth
- independent verifier
- verification rule
- outcome taxonomy
- evidence interpretation

Only the agent architecture changes.

---

## Outcome Labels

The existing P1/P2 taxonomy is retained:

- TRUE_SUCCESS
- FALSE_SUCCESS
- FAILURE
- FALSE_FAILURE

P3 must preserve the same classification logic.

---

## Critical Adversarial Case

A multi-agent system may unanimously report SUCCESS
while the observed outcome is WRONG.

The verifier MUST classify this as:

FALSE_SUCCESS

This demonstrates that:

Multi-Agent Consensus ≠ Reality

---

## Independence Requirement

The verifier MUST remain independent of:

- planner output
- executor report
- critic output
- final agent report

The verifier may use the observed outcome and predeclared
expected outcome.

---

## Pass Criteria

P3 passes only if:

1. Every fixture case executes successfully.
2. Single-agent and multi-agent conditions use the same verifier.
3. Wrong observations are classified as FALSE_SUCCESS when
   the reported status is SUCCESS.
4. Correct observations remain TRUE_SUCCESS even when the
   agent reports FAILURE.
5. Multi-agent agreement cannot override ground truth.
6. Verification remains independent of agent reporting.
7. All expected labels match the fixture.
8. The result summary reports 100% apparatus pass rate.

---

## Interpretation

A P3 pass does NOT establish:

- multi-agent superiority
- general agent reliability
- autonomous-system safety
- real-world performance
- JAS-SI novelty
- benchmark superiority

A P3 pass establishes only that the verification apparatus
continues to function when the agent condition is expanded
from a single-agent architecture to a controlled multi-agent
architecture.

---

## Research Boundary

P3 is deliberately deterministic.

It does not yet introduce:

- external LLM providers
- stochastic model comparison
- production APIs
- unrestricted computer use
- real-world consequential actions
- autonomous deployment

Those belong to later experimental stages after the apparatus
and benchmark controls are validated.

---

## Stop Rule

If any P3 case fails:

STOP.

Do not proceed to a larger multi-agent/autopilot integration
until the failed apparatus condition is investigated and
corrected under the master research protocol.

---

## Future Extension

A later controlled experiment may replace the deterministic
multi-agent simulator with an actual model stack:

Planner
→ Executor
→ Critic
→ Authorization Gate
→ Action
→ Independent Verification
→ Reality-Based Outcome

Any such extension requires:

- fixed model versions
- fixed prompts
- fixed tools
- fixed permissions
- controlled seeds where available
- frozen benchmark content
- predefined evaluation budget
- independent evidence
- baseline comparison

No novelty claim may be made from architecture composition alone.
