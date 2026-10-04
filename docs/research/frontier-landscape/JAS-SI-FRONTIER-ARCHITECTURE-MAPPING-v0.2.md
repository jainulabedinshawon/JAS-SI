JAS-SI — Frontier Architecture Mapping v0.2

Research Target: JAS-SI 2.0
Conceptual Baseline: JAS-SI 1.0
Master Protocol: v2.2 — FINAL / FROZEN
Status: Research Evidence Collected
Benchmark v0.1: NOT YET FROZEN

---

1. Executive Finding

The 2026 frontier landscape shows that many capabilities originally associated with the JAS-SI architecture already exist in mature or emerging agent platforms.

Therefore:

«JAS-SI must NOT claim novelty from persistent orchestration, tool use, computer use, memory, multi-agent coordination, permissions, governance, or agent evaluation alone.»

The strongest remaining research direction identified so far is narrower:

Agent Action
      ↓
Independent / Environment-Grounded Evidence
      ↓
Verified Reality
      ↓
Outcome Classification
      ↓
Correct Report
      ↓
Controlled Learning

The research question is therefore shifting from:

"Can an AI agent act?"

toward:

"Can an AI agent reliably distinguish what it intended,
what it reported, and what actually happened?"

This is a research hypothesis, not yet a validated novelty claim.

---

2. Frontier Systems Mapped

Initial mapping covers:

1. OpenAI Frontier
2. OpenAI Agents / Codex architecture
3. OpenAI Computer-Using Agent
4. Anthropic Claude Agent SDK / Claude Code
5. Google Gemini Enterprise Agent Platform / ADK
6. Google Computer Use
7. Frontier computer-use benchmark research
8. Environment-grounded verification research

Additional systems may be added before Baseline B selection.

---

3. Capability Matrix

Capability| OpenAI Frontier| Anthropic Agent SDK / Claude Code| Google Agent Platform / ADK| JAS-SI
Persistent orchestration| Present| Present| Present| Planned
Long-running tasks| Present| Present| Present| Planned
Tool use| Present| Present| Present| Required
Computer use| Present| Present| Present| Planned
Browser use| Present| Present| Present| Planned
Persistent / long-term memory| Present| Present| Present| Required
Multi-agent| Present / supported| Present| Present| Optional
Explicit permissions| Present| Present| Present| Required
Governance controls| Present| Present| Present| Required
Audit / observability| Present| Partial / supported| Present| Required
Planning| Present| Present| Present| Required
Self-correction| Present| Present| Present| Required
Evaluation loops| Present| Present| Present| Required
Simulation| Domain-dependent| Domain-dependent| Supported environments| Required
Independent outcome verification| Not established as unique| Not established as unique| Partial / system-dependent| Core research target
Reality-grounded final state| Not established as unique| Not established as unique| Partial / system-dependent| Core research target
False-success resistance| Research/evaluation area| Research/evaluation area| Research/evaluation area| Core benchmark
Verified-failure learning| Experience/evaluation loops| Experience/context mechanisms| Evaluation/optimization loops| Core research target
STOP / correction / revocation| Governance-dependent| Permissions / control mechanisms| Governance / policy mechanisms| Core benchmark
Accountability chain| Enterprise governance| Permission / tool framework| IAM / Agent Gateway| Core architecture
Independent evidence as outcome authority| Not established| Not established| Not established| Hypothesis

---

4. OpenAI Frontier

Evidence

OpenAI Frontier is explicitly designed for enterprise AI coworkers operating across business systems.

Documented capabilities include:

- enterprise context;
- durable institutional memory;
- agent execution;
- parallel agent operation;
- evaluation and optimization loops;
- identity;
- explicit permissions;
- auditable actions;
- monitoring and logs;
- governance.

Therefore these capabilities are not JAS-SI novelty by themselves.

Classification

Persistent Memory:
D — Existing and Comparable

Agent Execution:
D — Existing and Comparable

Permissions:
D — Existing and Comparable

Governance:
D — Existing and Comparable

Auditing:
D — Existing and Comparable

Learning / Optimization:
C/D — Existing but implementation and evaluation differ

Independent Verification:
E — Insufficient evidence for a direct JAS-SI-equivalent claim

Reality-Based Outcome Verification:
E — Requires controlled comparison

---

5. OpenAI Agent / Codex Architecture

OpenAI's agent architecture separates:

Agent Harness
Environment
Application Server

The harness maintains the model/tool loop and session, while the environment provides compute, files, or execution capabilities.

This demonstrates that:

- persistent agent execution;
- tool loops;
- external environments;
- application-level orchestration

are already established frontier patterns.

Therefore these components cannot independently establish JAS-SI novelty.

---

6. OpenAI Computer Use

OpenAI's Computer-Using Agent demonstrates:

Perception
→ Reasoning
→ Action
→ Updated Perception
→ Adaptation

It can operate graphical interfaces and adapt to changing screen states.

Sensitive actions may require user confirmation.

Therefore:

Perception + Planning + Computer Action

is already an established capability.

JAS-SI should not claim computer use itself as novel.

The relevant research question is instead:

After computer action,
what independently establishes that the intended state was actually achieved?

---

7. Anthropic Claude Agent SDK / Claude Code

Anthropic documents a mature agent framework with:

- long-running autonomous work;
- context management;
- permissions frameworks;
- subagents;
- hooks;
- background tasks;
- checkpoints;
- tool access;
- computer-use capabilities;
- prompt-injection defenses.

Therefore:

Agent + Tools + Permissions + Subagents + Long-Running Execution

is clearly not unique to JAS-SI.

A particularly important finding is that Anthropic explicitly identifies permission systems and user control as part of agent infrastructure.

This weakens any claim that:

«"AI agents need explicit permissions"»

is itself a novel JAS-SI contribution.

The possible research contribution must be more specific.

---

8. Google Gemini Enterprise Agent Platform

Google's Agent Platform provides an especially strong comparable architecture.

Documented components include:

Agent
Runtime
Sessions
Long-Term Memory
Agent Registry
Agent Identity
Agent Gateway
Policy Enforcement
Evaluation
Observability
Multi-Agent Orchestration

This means that several elements of the JAS-SI target architecture already exist in enterprise-grade form.

Therefore the following cannot independently be claimed as novel:

- persistent cloud agent;
- long-term memory;
- agent identity;
- centralized tool access;
- policy enforcement;
- multi-agent orchestration;
- runtime management;
- evaluation;
- observability.

---

9. Google Computer Use

Google's computer-use architecture explicitly implements an agent loop:

Task
 ↓
Screenshot + Context
 ↓
Model
 ↓
UI Action
 ↓
Computer Environment
 ↓
Updated State
 ↓
Next Action

The system can also expose safety responses that may block actions or require user decisions.

This establishes that:

Perceive → Decide → Act → Observe

is already common frontier architecture.

The JAS-SI research opportunity therefore moves one layer deeper:

Observe
→ Establish Ground Truth
→ Determine Actual Outcome
→ Compare Against Intended Outcome
→ Report Verified State

---

10. Frontier Benchmark Evidence

2026 benchmark research shows that computer-use capability remains substantially imperfect.

WindowsWorld reports that leading computer-use agents perform poorly on complex multi-application workflows, with success below 21% on its multi-application tasks.

This is important because it demonstrates that:

Computer Use ≠ Reliable Real-World Execution

The benchmark also shows failures involving:

- cross-application reasoning;
- conditional judgment;
- long multi-step workflows;
- execution efficiency.

Therefore JAS-SI should not assume that adding computer use creates reliable intelligence.

---

11. AgencyBench

AgencyBench evaluates autonomous agents across:

- long-horizon scenarios;
- multiple agentic capabilities;
- real-world-style tasks;
- tool calls;
- extended context;
- feedback;
- automated evaluation.

The benchmark contains 138 tasks across 32 scenarios and reports large differences between closed- and open-source systems.

This provides further evidence that:

Agent Capability

must be measured experimentally rather than inferred from architecture.

---

12. Independent Verification Finding

Recent 2026 research directly strengthens the JAS-SI research direction.

Environment-grounded auditing research reports that LLM self-reports can substantially overstate actual success and concludes that self-reports should be treated as claims requiring environmental verification.

Another 2026 study of long-running autonomous agent loops reports substantial self-evaluation bias when agents judge their own progress, including cases where claimed improvement corresponded to zero or negative measured change.

These findings provide external motivation for the JAS-SI distinction:

SELF-REPORT
≠
VERIFICATION

and:

PREDICTED / CLAIMED OUTCOME
≠
OBSERVED REALITY

This is currently one of the strongest evidence-backed research directions identified.

---

13. Revised Gap Register

Gap| Current Evidence| JAS-SI Research Relevance
Tool use| Strongly existing| Low novelty potential
Computer use| Strongly existing| Low novelty potential
Persistent memory| Strongly existing| Low novelty potential
Cloud orchestration| Strongly existing| Low novelty potential
Multi-agent execution| Strongly existing| Low novelty potential
Permissions| Existing| Low novelty potential alone
Identity| Existing| Low novelty potential alone
Governance| Existing| Low novelty potential alone
Evaluation| Existing| Low novelty potential alone
Long-horizon execution| Existing| Low novelty potential alone
Self-correction| Existing| Low novelty potential alone
Independent verification| Partially explored| High research relevance
Environment-grounded outcome authority| Not established as universal capability| High research relevance
False-success resistance| Important but fragmented| High benchmark relevance
Verified-failure learning| Not established as equivalent architecture| High research relevance
Verification after interruption| Insufficient comparable evidence| High research relevance
Unified Intent→Auth→Action→Evidence→Verification chain| No direct equivalence established| Candidate research area
Reality/report separation| Research evidence supports importance| Candidate research area

---

14. What JAS-SI Must Abandon as Novelty Claims

The following claims are now considered insufficient for novelty:

"JAS-SI uses persistent memory."

"JAS-SI has an orchestrator."

"JAS-SI can use tools."

"JAS-SI can use computers."

"JAS-SI uses multiple agents."

"JAS-SI has permissions."

"JAS-SI has governance."

"JAS-SI can learn from experience."

"JAS-SI evaluates agents."

"JAS-SI uses cloud infrastructure."

These are existing frontier capabilities.

---

15. Stronger Candidate Research Direction

The current evidence supports investigation of the following architecture:

INTENT
   ↓
PLAN
   ↓
AUTHORIZATION
   ↓
ACTION
   ↓
OBSERVED REALITY
   ↓
INDEPENDENT EVIDENCE
   ↓
VERIFICATION
   ↓
VERIFIED STATE
   ↓
REPORT
   ↓
CONTROLLED LEARNING

The key distinction is:

Agent says:
"I succeeded."

versus

System establishes:
"The required state exists,
independently supported by evidence."

---

16. Candidate Novelty Hypothesis N1

Hypothesis

A system architecture that explicitly separates:

Intent
Report
Reality
Evidence
Verified State

and makes independently verified state authoritative for outcome classification may reduce false-success acceptance compared with agent self-report or same-model evaluation.

Required experiment

At minimum:

Same Task
Same Agent
Same Environment
Same Seed
Same Action Surface

Compare:

Condition A
Agent Self-Report

Condition B
Same-Model Verification

Condition C
Independent Verification

Primary outcome:

FALSE_SUCCESS
/
(TRUE_SUCCESS + FALSE_SUCCESS)

Secondary outcomes:

- false-success detection;
- false-failure detection;
- evidence completeness;
- verifier disagreement;
- abstention quality.

---

17. Candidate Novelty Hypothesis N2

Hypothesis

Explicit authorization gating may reduce unauthorized consequential actions under adversarial or ambiguous task conditions.

Required comparison

No Explicit Authorization Gate
vs.
Explicit Authorization Gate

Primary metric:

Block D Unauthorized Action Rate

Unauthorized action includes:

- action outside granted scope;
- action after expiry;
- action after revocation;
- bypass of authorization gate;
- prohibited alternative route.

---

18. Candidate Novelty Hypothesis N3

Hypothesis

A verified-failure learning loop may reduce recurrence of analogous failures more reliably than memory storage without outcome verification.

Required experiment

Baseline
→ Failure
→ Independent Verification
→ Controlled Update
→ Analogous Task
→ Recurrence Measurement

Comparison:

Memory Storage Only
vs.
Verified Failure → Controlled Learning

A memory write must not be counted as learning.

---

19. Candidate Novelty Hypothesis N4

Hypothesis

Explicit verification after interruption, revocation, or permission reduction may improve post-interruption state accuracy.

Required tests:

STOP
PAUSE
REVOCATION
PERMISSION REDUCTION
CORRECTION
SHUTDOWN

The system must be evaluated on both:

Did the action stop?

and:

What state actually exists after stopping?

---

20. Revised Research Priority

Based on current evidence:

Priority 1 — Independent Verification

Highest current relevance.

Priority 2 — False-Success Resistance

Directly measurable and benchmarkable.

Priority 3 — Authorization Under Adversarial Conditions

Important but permissions already exist in frontier systems.

Priority 4 — Verified Failure Learning

Potentially strong if empirically separated from ordinary memory.

Priority 5 — Corrigibility + State Verification

Strong governance research opportunity.

Priority 6 — Integrated Accountability Chain

Potential architectural contribution, but must be benchmarked.

Low Priority as Novelty

Memory
Tool Use
Browser Use
Computer Use
Cloud Orchestration
Multi-Agent
Basic Permissions
Basic Governance

These remain engineering requirements but are not currently strong novelty claims.

---

21. Baseline B Decision

Baseline B is NOT YET SELECTED.

Selection must occur after:

1. completing the frontier mapping;
2. identifying the most comparable systems;
3. confirming tool/environment compatibility;
4. determining whether verification configurations can be reproduced;
5. evaluating benchmark compatibility;
6. avoiding cherry-picking.

Candidate comparison classes should include:

Frontier General Agent
Computer-Use Agent
Coding / Repository Agent
Enterprise Governed Agent
Independent-Verifier Configuration

The final Baseline B must be evidence-selected.

---

22. Research Gap Statement

Current evidence does not support the claim that JAS-SI invented:

AI agents
persistent agents
memory
tool use
computer use
multi-agent systems
permissions
governance
agent evaluation

Current evidence does support further investigation into:

Independent Verification
+
Environment-Grounded Evidence
+
False-Success Resistance
+
Verified Failure Learning
+
Post-Interruption State Verification
+
Integrated Accountability

These remain research hypotheses, not validated contributions.

---

23. Required Next Experiment

The next major design task should therefore be:

JAS-SI Verification Benchmark v0.1

with the core comparison:

V0 — No Verifier
V1 — Same-Model Verifier
V2 — Independent Verifier

and the central research question:

«Does independent, environment-grounded verification reduce false-success acceptance compared with agent self-report or same-model verification?»

---

24. Current Status

JAS-SI 1.0 Baseline: FROZEN
Master Protocol v2.2: FINAL / FROZEN

Frontier Architecture Mapping: SUBSTANTIALLY MAPPED
Existing-System Mapping: IN PROGRESS
Gap Analysis: INITIAL
Novelty Hypotheses: REFINED
Baseline A: PENDING
Baseline B: PENDING
Benchmark v0.1: NOT YET FROZEN

Measured JAS-SI Superiority: NOT ESTABLISHED
Validated Novelty Claim: NOT YET ESTABLISHED

---

25. Research Principle

The frontier mapping changes the research strategy.

JAS-SI should not attempt to prove:

"We built an agent."

It should test:

"Can an agent reliably distinguish
what it intended,
what it did,
what it claims,
and what actually happened?"

The decisive research chain remains:

Existing Capability
      ↓
Research Gap
      ↓
Hypothesis
      ↓
Benchmark
      ↓
Controlled Experiment
      ↓
Measured Difference
      ↓
Uncertainty
      ↓
Alternative Explanation
      ↓
Validated Claim

No measured difference → no superiority claim.

No independent evidence → no verified outcome claim.

Architecture alone → insufficient novelty evidence.
