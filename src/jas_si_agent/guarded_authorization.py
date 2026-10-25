
"""Fail-closed authorization service guarded by audit integrity.

This module evaluates policy only. It never executes actions.
The local checkpoint is not an independent trust anchor.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from jas_si_agent.audit_store import JsonlAuditStore
from jas_si_agent.authorization import (
    ActionRequest,
    AuthorizationDecision,
    AuthorizationGate,
    AuthorizationGrant,
)
from jas_si_agent.checkpoint_store import JsonCheckpointStore
from jas_si_agent.integrity_guard import (
    IntegrityCheckResult,
    verify_startup_integrity,
)


class IntegrityGuardedAuthorizationService:
    """Require valid audit integrity before evaluating authorization."""

    def __init__(
        self,
        audit_store: JsonlAuditStore,
        checkpoint_store: JsonCheckpointStore,
        authorization_gate: Optional[AuthorizationGate] = None,
    ) -> None:
        self._audit_store = audit_store
        self._checkpoint_store = checkpoint_store
        self._authorization_gate = (
            authorization_gate or AuthorizationGate()
        )

    def authorize(
        self,
        request: ActionRequest,
        grant: Optional[AuthorizationGrant] = None,
        now: Optional[datetime] = None,
    ) -> tuple[IntegrityCheckResult, AuthorizationDecision]:
        """Return an integrity result and a fail-closed decision."""

        try:
            integrity = verify_startup_integrity(
                self._audit_store,
                self._checkpoint_store,
            )
        except Exception:
            # Unexpected integrity-check errors must not permit access.
            integrity = IntegrityCheckResult(
                valid=False,
                reason="UNEXPECTED_INTEGRITY_CHECK_ERROR",
                record_count=0,
                checkpoint_sequence=None,
            )

        action_id = (
            request.action_id
            if isinstance(request, ActionRequest)
            and isinstance(request.action_id, str)
            else ""
        )

        if not integrity.valid:
            return integrity, AuthorizationDecision(
                allowed=False,
                reason=(
                    "STARTUP_INTEGRITY_CHECK_FAILED:"
                    f"{integrity.reason}"
                ),
                action_id=action_id,
            )

        if not isinstance(request, ActionRequest):
            return integrity, AuthorizationDecision(
                allowed=False,
                reason="INVALID_ACTION_REQUEST",
                action_id="",
            )

        try:
            decision = self._authorization_gate.evaluate(
                request,
                grant=grant,
                now=now,
            )
        except Exception:
            # Malformed input or an unexpected policy error denies access.
            decision = AuthorizationDecision(
                allowed=False,
                reason="AUTHORIZATION_EVALUATION_ERROR",
                action_id=action_id,
            )

        return integrity, decision
