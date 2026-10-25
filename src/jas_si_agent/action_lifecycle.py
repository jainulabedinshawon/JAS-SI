
"""Coordinate authorization and outcome verification without executing actions.

Only authorization decisions issued by this coordinator instance are
accepted. Each issued decision is consumed at most once within this
process, including when verification input is malformed.

This module does not execute actions, authenticate grants cryptographically,
or independently establish that an external action actually occurred.
"""

from __future__ import annotations

from datetime import datetime
from threading import RLock
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
        self._gate = (
            authorization_gate
            if authorization_gate is not None
            else AuthorizationGate()
        )

        # Keep strong references to decisions issued by this instance.
        # This is process-local provenance, not cryptographic authentication.
        self._issued_decisions: dict[int, AuthorizationDecision] = {}

        # Protect decision registration and consumption against concurrent
        # calls within this coordinator instance.
        self._decision_lock = RLock()

    def authorize(
        self,
        request: ActionRequest,
        grant: Optional[AuthorizationGrant] = None,
        now: Optional[datetime] = None,
    ) -> AuthorizationDecision:
        """Evaluate a request and register the resulting decision.

        This method makes a policy decision only. It does not execute
        the requested action.
        """
        decision = self._gate.evaluate(
            request,
            grant=grant,
            now=now,
        )

        if not isinstance(decision, AuthorizationDecision):
            raise TypeError(
                "AuthorizationGate must return an AuthorizationDecision"
            )

        with self._decision_lock:
            self._issued_decisions[id(decision)] = decision

        return decision

    def _consume_decision(
        self,
        decision: AuthorizationDecision,
    ) -> bool:
        """Consume a decision once if this instance issued that exact object."""
        with self._decision_lock:
            registered = self._issued_decisions.pop(
                id(decision),
                None,
            )

            return registered is decision

    @staticmethod
    def _inconclusive(
        reason: str,
        action_id: str = "",
    ) -> VerificationResult:
        """Construct a fail-closed result for invalid or untrusted input."""
        return VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            reason=reason,
            action_id=action_id,
        )

    def verify_outcome(
        self,
        decision: AuthorizationDecision,
        report: ActionReport,
        evidence: Optional[VerificationEvidence],
    ) -> VerificationResult:
        """Verify an outcome only after consuming a trusted local decision.

        The decision is consumed before report validation so that a malformed
        report cannot be used to preserve and replay the same decision.
        """

        # Reject objects that are not authorization decisions.
        if not isinstance(decision, AuthorizationDecision):
            return self._inconclusive(
                "INVALID_AUTHORIZATION_DECISION"
            )

        # Only the exact object issued by this coordinator is accepted.
        # A separately constructed decision with identical fields is rejected.
        if not self._consume_decision(decision):
            return self._inconclusive(
                "INVALID_AUTHORIZATION_DECISION"
            )

        # Validate the report after consuming the decision.
        if not isinstance(report, ActionReport):
            return self._inconclusive(
                "INVALID_ACTION_REPORT"
            )

        if not isinstance(report.action_id, str):
            return self._inconclusive(
                "INVALID_ACTION_ID"
            )

        action_id = report.action_id

        if not action_id.strip():
            return self._inconclusive(
                "INVALID_ACTION_ID",
                action_id,
            )

        # Require a real Boolean True, not 1 or another truthy value.
        if decision.allowed is not True:
            return self._inconclusive(
                "ACTION_NOT_AUTHORIZED",
                action_id,
            )

        # Validate the decision's action identifier independently.
        if (
            not isinstance(decision.action_id, str)
            or not decision.action_id.strip()
        ):
            return self._inconclusive(
                "INVALID_AUTHORIZATION_DECISION",
                action_id,
            )

        # The report must match the exact action that was authorized.
        if decision.action_id != action_id:
            return self._inconclusive(
                "ACTION_ID_MISMATCH",
                action_id,
            )

        # Delegate evidence and outcome checks to the existing verifier.
        return verify_report(report, evidence)
