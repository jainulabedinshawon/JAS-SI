
"""JAS-SI MVP: fail-closed authorization policy gate.

This module decides whether an action may proceed.
It does not execute tools, modify files, or grant OS permissions.

JAS-SI 1.0 and the frozen research protocol remain unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


# Safe here means eligible for policy approval, not inherently harmless.
# The eventual executor must still enforce resource and tool restrictions.
SAFE_ACTIONS = frozenset({
    "read_repository",
    "run_tests",
    "propose_patch",
})

# These actions require a separate, explicit human authorization grant.
GRANT_REQUIRED_ACTIONS = frozenset({
    "write_file",
    "create_pull_request",
})

# Not supported by this MVP. A grant cannot override this restriction.
NEVER_ALLOWED_ACTIONS = frozenset({
    "execute_shell",
    "merge_pull_request",
    "delete_resource",
})

SUPPORTED_ACTIONS = (
    SAFE_ACTIONS
    | GRANT_REQUIRED_ACTIONS
    | NEVER_ALLOWED_ACTIONS
)


@dataclass(frozen=True)
class ActionRequest:
    """A request to perform one bounded action."""

    action_id: str
    action_type: str
    resource: str


@dataclass(frozen=True)
class AuthorizationGrant:
    """An explicit, scoped, time-limited human approval."""

    grant_id: str
    approved_by: str
    human_approved: bool
    allowed_actions: tuple[str, ...]
    allowed_resources: tuple[str, ...]
    expires_at: datetime


@dataclass(frozen=True)
class AuthorizationDecision:
    """Auditable decision returned by the policy gate."""

    allowed: bool
    reason: str
    action_id: str
    grant_id: Optional[str] = None


class AuthorizationGate:
    """Deny by default; never execute the requested action."""

    def evaluate(
        self,
        request: ActionRequest,
        grant: Optional[AuthorizationGrant] = None,
        now: Optional[datetime] = None,
    ) -> AuthorizationDecision:
        action_id = (
            request.action_id
            if isinstance(request.action_id, str)
            else ""
        )

        def deny(
            reason: str,
            grant_id: Optional[str] = None,
        ) -> AuthorizationDecision:
            return AuthorizationDecision(
                allowed=False,
                reason=reason,
                action_id=action_id,
                grant_id=grant_id,
            )

        # Fail closed on malformed requests.
        if not action_id.strip():
            return deny("INVALID_ACTION_ID")

        if not isinstance(request.action_type, str):
            return deny("INVALID_ACTION_TYPE")

        if not isinstance(request.resource, str):
            return deny("INVALID_RESOURCE")

        if not request.resource.strip():
            return deny("EMPTY_RESOURCE")

        if request.resource.strip() == "*":
            return deny("WILDCARD_RESOURCE_NOT_ALLOWED")

        action_type = request.action_type

        if action_type not in SUPPORTED_ACTIONS:
            return deny("UNKNOWN_ACTION_TYPE")

        if action_type in NEVER_ALLOWED_ACTIONS:
            return deny("ACTION_DISABLED_IN_MVP")

        # Limited, non-mutating operations are eligible by policy.
        # This is not proof that the eventual executor is safe.
        if action_type in SAFE_ACTIONS:
            return AuthorizationDecision(
                allowed=True,
                reason="SAFE_ACTION_POLICY_ALLOWED",
                action_id=action_id,
            )

        # All other supported actions require explicit human approval.
        if action_type not in GRANT_REQUIRED_ACTIONS:
            return deny("NO_ALLOW_RULE")

        if grant is None:
            return deny("HUMAN_APPROVAL_REQUIRED")

        if not isinstance(grant, AuthorizationGrant):
            return deny("INVALID_GRANT")

        if not grant.human_approved:
            return deny("HUMAN_APPROVAL_NOT_CONFIRMED")

        if not grant.grant_id.strip():
            return deny("INVALID_GRANT_ID")

        if not grant.approved_by.strip():
            return deny("MISSING_APPROVER")

        current_time = now or datetime.now(timezone.utc)

        # Require timezone-aware timestamps.
        if (
            current_time.tzinfo is None
            or current_time.utcoffset() is None
            or grant.expires_at.tzinfo is None
            or grant.expires_at.utcoffset() is None
        ):
            return deny("TIMEZONE_REQUIRED", grant.grant_id)

        if current_time >= grant.expires_at:
            return deny("GRANT_EXPIRED", grant.grant_id)

        if action_type not in grant.allowed_actions:
            return deny("ACTION_OUTSIDE_GRANT_SCOPE", grant.grant_id)

        # Exact resource matching only. No implicit wildcard permissions.
        if request.resource not in grant.allowed_resources:
            return deny("RESOURCE_OUTSIDE_GRANT_SCOPE", grant.grant_id)

        return AuthorizationDecision(
            allowed=True,
            reason="EXPLICIT_HUMAN_GRANT_ACCEPTED",
            action_id=action_id,
            grant_id=grant.grant_id,
        )
