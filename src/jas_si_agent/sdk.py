
"""Public Developer SDK for JAS-SI.

This SDK exposes the existing authorization and verification primitives.
It does not execute actions or treat an agent's success claim as proof.

Compatible with Python 3.10.
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
    verify_report,
)


class JASSI:
    """Public entry point for JAS-SI authorization and verification."""

    def __init__(
        self,
        authorization_gate: Optional[AuthorizationGate] = None,
    ) -> None:
        if authorization_gate is not None and not isinstance(
            authorization_gate, AuthorizationGate
        ):
            raise TypeError(
                "authorization_gate must be an AuthorizationGate"
            )

        self._authorization_gate = (
            authorization_gate
            if authorization_gate is not None
            else AuthorizationGate()
        )

    def authorize(
        self,
        action_id: str,
        action: str,
        resource: str,
        grant: Optional[AuthorizationGrant] = None,
        now: Optional[datetime] = None,
    ) -> AuthorizationDecision:
        """Evaluate whether an action is authorized.

        This method evaluates policy only. It never executes the action.
        Grant-required actions are denied when a valid grant is absent.
        """
        request = ActionRequest(
            action_id=action_id,
            action_type=action,
            resource=resource,
        )

        return self._authorization_gate.evaluate(
            request,
            grant=grant,
            now=now,
        )

    def verify(
        self,
        report: ActionReport,
        evidence: Optional[VerificationEvidence],
    ) -> VerificationResult:
        """Compare a reported outcome with separately supplied evidence.

        Missing or insufficient evidence must not be treated as success.
        Evidence-source trust must be assessed independently.
        """
        return verify_report(report, evidence)


__all__ = ["JASSI"]
