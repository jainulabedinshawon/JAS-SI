
"""Coordinate authorization and outcome verification without executing actions.

Authorization decisions must originate from this coordinator's own
authorization flow. Each issued decision can be consumed only once.

This module does not execute actions or independently establish that
an external action actually occurred.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from jas_si_agent.authorization import (
    ActionRequest,
    AuthorizationDecision,
    AuthorizationGate,
    AuthorizationGrant,
)
from jas_si_agent.verification import (
    ActionReport,
    VerificationEvidence,
    VerificationResult,
    VerificationStatus,
    verify_report,
)


class ActionLifecycleCoordinator:
    """Apply authorization before accepting an outcome for verification."""

    def __init__(
        self,
        authorization_gate: Optional[AuthorizationGate] = None,
    ) -> None:
        self._gate = authorization_gate or AuthorizationGate()

        # In-process provenance only; this is not durable replay protection.
        self._issued_decisions: dict[int, AuthorizationDecision] = {}

    def authorize(
        self,
        request: ActionRequest,
        grant: Optional[AuthorizationGrant] = None,
        now: Optional[datetime] = None,
    ) -> AuthorizationDecision:
        """Issue and register a policy decision; never execute an action."""
        decision = self._gate.evaluate(
            request,
            grant=grant,
            now=now,
        )

        if isinstance(decision, AuthorizationDecision):
            self._issued_decisions[id(decision)] = decision

        return decision

    def verify_outcome(
        self,
        decision: AuthorizationDecision,
        report: ActionReport,
        evidence: Optional[VerificationEvidence],
    ) -> VerificationResult:
        """Verify a report only after validating decision provenance."""

        if not isinstance(report, ActionReport):
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                reason="INVALID_ACTION_REPORT",
                action_id="",
            )

        action_id = (
            report.action_id
            if isinstance(report.action_id, str)
            else ""
        )

        def inconclusive(reason: str) -> VerificationResult:
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                reason=reason,
                action_id=action_id,
            )

        if not isinstance(decision, AuthorizationDecision):
            return inconclusive("INVALID_AUTHORIZATION_DECISION")

        # Require the exact decision instance issued by this coordinator.
        # Pop it immediately so the same decision cannot be replayed.
        registered = self._issued_decisions.pop(id(decision), None)

        if registered is not decision:
            return inconclusive("INVALID_AUTHORIZATION_DECISION")

        # Do not accept truthy non-Boolean values such as integer 1.
        if decision.allowed is not True:
            return inconclusive("ACTION_NOT_AUTHORIZED")

        if not action_id.strip():
            return inconclusive("INVALID_ACTION_ID")

        if decision.action_id != action_id:
            return inconclusive("ACTION_ID_MISMATCH")

        return verify_report(report, evidence)
