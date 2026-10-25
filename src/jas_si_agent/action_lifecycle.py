"""Coordinate authorization and outcome verification without executing actions.

This module connects the authorization gate to the verification primitives.
It does not execute actions, collect evidence, or change external state.
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

    def authorize(
        self,
        request: ActionRequest,
        grant: Optional[AuthorizationGrant] = None,
        now: Optional[datetime] = None,
    ) -> AuthorizationDecision:
        """Return a policy decision. Never execute the requested action."""
        return self._gate.evaluate(request, grant=grant, now=now)

    def verify_outcome(
        self,
        decision: AuthorizationDecision,
        report: ActionReport,
        evidence: Optional[VerificationEvidence],
    ) -> VerificationResult:
        """Verify a report only when its action was authorized."""

        # Validate the report before accessing any of its attributes.
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

        # Authorization must be valid before outcome verification.
        if not isinstance(decision, AuthorizationDecision):
            return inconclusive("INVALID_AUTHORIZATION_DECISION")

        if not decision.allowed:
            return inconclusive("ACTION_NOT_AUTHORIZED")

        # Reject malformed or empty action identifiers.
        if not action_id.strip():
            return inconclusive("INVALID_ACTION_ID")

        # The report must refer to the authorized action.
        if decision.action_id != action_id:
            return inconclusive("ACTION_ID_MISMATCH")

        # Delegate evidence and outcome checks to the verifier.
        return verify_report(report, evidence)
