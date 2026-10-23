
"""Fail-closed authorization service guarded by audit integrity.

This service checks persisted audit integrity before asking the
authorization policy to evaluate a request.

It never executes actions or changes external state.
A local checkpoint is not an independent trust anchor.
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
    """Require valid local audit integrity before authorization."""

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
        """Return integrity status and a fail-closed policy decision."""

        integrity = verify_startup_integrity(
            self._audit_store,
            self._checkpoint_store,
        )

        action_id = (
            request.action_id
            if isinstance(request, ActionRequest)
            and isinstance(request.action_id, str)
            else ""
        )

        if not integrity.valid:
            decision = AuthorizationDecision(
                allowed=False,
                reason=(
                    "STARTUP_INTEGRITY_CHECK_FAILED:"
                    f"{integrity.reason}"
                ),
                action_id=action_id,
            )
            return integrity, decision

        decision = self._authorization_gate.evaluate(
            request,
            grant=grant,
            now=now,
        )
        return integrity, decision
