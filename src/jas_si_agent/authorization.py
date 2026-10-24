
"""JAS-SI MVP: fail-closed authorization policy gate.

This module decides whether an action may proceed.
It does not execute tools, modify files, or grant OS permissions.

JAS-SI 1.0 and the frozen research protocol remain unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


# Eligible for policy approval does not mean inherently harmless.
SAFE_ACTIONS = frozenset({
    "read_repository",
    "run_tests",
    "propose_patch",
})

GRANT_REQUIRED_ACTIONS = frozenset({
    "write_file",
    "create_pull_request",
})

# A grant cannot override these MVP restrictions.
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
            if isinstance(request, ActionRequest)
            and isinstance(request.action_id, str)
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

        # Validate the request object and its fields first.
        if not isinstance(request, ActionRequest):
            return deny("INVALID_ACTION_REQUEST")

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

        # These actions are eligible by policy only.
        # This module does not execute them.
        if action_type in SAFE_ACTIONS:
            return AuthorizationDecision(
                allowed=True,
                reason="SAFE_ACTION_POLICY_ALLOWED",
                action_id=action_id,
            )

        if action_type not in GRANT_REQUIRED_ACTIONS:
            return deny("NO_ALLOW_RULE")

        if grant is None:
            return deny("HUMAN_APPROVAL_REQUIRED")

        if not isinstance(grant, AuthorizationGrant):
            return deny("INVALID_GRANT")

        # Require an actual Boolean True, not an integer such as 1.
        if grant.human_approved is not True:
            return deny("HUMAN_APPROVAL_NOT_CONFIRMED")

        # Validate identifiers before calling string methods.
        if (
            not isinstance(grant.grant_id, str)
            or not grant.grant_id.strip()
        ):
            return deny("INVALID_GRANT_ID")

        if (
            not isinstance(grant.approved_by, str)
            or not grant.approved_by.strip()
        ):
            return deny("MISSING_APPROVER")

        # Grant scope must be explicit and structurally valid.
        if (
            not isinstance(grant.allowed_actions, tuple)
            or not grant.allowed_actions
            or any(
                not isinstance(item, str) or not item.strip()
                for item in grant.allowed_actions
            )
        ):
            return deny("INVALID_GRANT_ACTIONS", grant.grant_id)

        if (
            not isinstance(grant.allowed_resources, tuple)
            or not grant.allowed_resources
            or any(
                not isinstance(item, str) or not item.strip()
                for item in grant.allowed_resources
            )
        ):
            return deny("INVALID_GRANT_RESOURCES", grant.grant_id)

        if not isinstance(grant.expires_at, datetime):
            return deny("INVALID_GRANT_EXPIRY", grant.grant_id)

        if now is not None and not isinstance(now, datetime):
            return deny("INVALID_CURRENT_TIME", grant.grant_id)

        current_time = now if now is not None else datetime.now(timezone.utc)

        # Both timestamps must be timezone-aware.
        if (
            current_time.tzinfo is None
            or current_time.utcoffset() is None
            or grant.expires_at.tzinfo is None
            or grant.expires_at.utcoffset() is None
        ):
            return deny("TIMEZONE_REQUIRED", grant.grant_id)

        # An expiry at the current instant is already expired.
        try:
            if current_time >= grant.expires_at:
                return deny("GRANT_EXPIRED", grant.grant_id)
        except (TypeError, ValueError, OverflowError):
            return deny("INVALID_GRANT_EXPIRY", grant.grant_id)

        if action_type not in grant.allowed_actions:
            return deny("ACTION_OUTSIDE_GRANT_SCOPE", grant.grant_id)

        # Exact resource matching only; no wildcard permissions.
        if request.resource not in grant.allowed_resources:
            return deny("RESOURCE_OUTSIDE_GRANT_SCOPE", grant.grant_id)

        return AuthorizationDecision(
            allowed=True,
            reason="EXPLICIT_HUMAN_GRANT_ACCEPTED",
            action_id=action_id,
            grant_id=grant.grant_id,
        )
