"""JAS-SI MVP: fail-closed authorization policy gate.

This module decides whether an action may proceed. It does not execute tools, modify files, or grant OS permissions.

Resources are repository-relative identifiers, not arbitrary OS paths. JAS-SI 1.0 and the frozen research protocol remain unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath, PureWindowsPath
from typing import Optional

SAFE_ACTIONS = frozenset(
    {
        "read_repository",
        "run_tests",
        "propose_patch",
    }
)

GRANT_REQUIRED_ACTIONS = frozenset(
    {
        "write_file",
        "create_pull_request",
    }
)

NEVER_ALLOWED_ACTIONS = frozenset(
    {
        "execute_shell",
        "merge_pull_request",
        "delete_resource",
    }
)

SUPPORTED_ACTIONS = (
    SAFE_ACTIONS | GRANT_REQUIRED_ACTIONS | NEVER_ALLOWED_ACTIONS
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


def _resource_is_safe(resource: str) -> bool:
    """Accept repository-relative identifiers without traversal syntax.

    This is lexical validation only. It does not resolve symlinks or prove that a later filesystem operation remains inside a repository root.
    """
    if not resource or resource != resource.strip():
        return False
    if "\x00" in resource or "\\" in resource:
        return False
    if resource.startswith("/") or resource.startswith("//"):
        return False
    windows_path = PureWindowsPath(resource)
    if windows_path.is_absolute() or windows_path.drive:
        return False
    parts = resource.split("/")
    # Reject ambiguous or traversal path components.
    if any(part in ("", ".", "..") for part in parts):
        return False
    # Reject wildcard-based resource identifiers.
    if any("*" in part for part in parts):
        return False
    # Confirm the identifier remains a relative POSIX-style path.
    parsed = PurePosixPath(resource)
    return not parsed.is_absolute() and ".." not in parsed.parts


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
        if not _resource_is_safe(request.resource):
            return deny("UNSAFE_RESOURCE_PATH")

        action_type = request.action_type
        if action_type not in SUPPORTED_ACTIONS:
            return deny("UNKNOWN_ACTION_TYPE")
        if action_type in NEVER_ALLOWED_ACTIONS:
            return deny("ACTION_DISABLED_IN_MVP")

        # Policy approval does not mean the action is inherently harmless.
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
        if grant.human_approved is not True:
            return deny("HUMAN_APPROVAL_NOT_CONFIRMED")
        if not isinstance(grant.grant_id, str) or not grant.grant_id.strip():
            return deny("INVALID_GRANT_ID", grant.grant_id)
        if (
            not isinstance(grant.approved_by, str)
            or not grant.approved_by.strip()
        ):
            return deny("MISSING_APPROVER", grant.grant_id)
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
                not isinstance(item, str) or not _resource_is_safe(item)
                for item in grant.allowed_resources
            )
        ):
            return deny("INVALID_GRANT_RESOURCES", grant.grant_id)
        if not isinstance(grant.expires_at, datetime):
            return deny("INVALID_GRANT_EXPIRY", grant.grant_id)
        if now is not None and not isinstance(now, datetime):
            return deny("INVALID_CURRENT_TIME", grant.grant_id)

        current_time = (
            now if now is not None else datetime.now(timezone.utc)
        )
        try:
            current_offset = current_time.utcoffset()
        except Exception:
            return deny("INVALID_CURRENT_TIME", grant.grant_id)

        try:
            expiry_offset = grant.expires_at.utcoffset()
        except Exception:
            return deny("INVALID_GRANT_EXPIRY", grant.grant_id)

        if current_offset is None or expiry_offset is None:
            return deny("TIMEZONE_REQUIRED", grant.grant_id)

        try:
            if current_time >= grant.expires_at:
                return deny("GRANT_EXPIRED", grant.grant_id)
        except Exception:
            return deny("INVALID_GRANT_EXPIRY", grant.grant_id)

        if action_type not in grant.allowed_actions:
            return deny("ACTION_OUTSIDE_GRANT_SCOPE", grant.grant_id)
        if request.resource not in grant.allowed_resources:
            return deny("RESOURCE_OUTSIDE_GRANT_SCOPE", grant.grant_id)

        return AuthorizationDecision(
            allowed=True,
            reason="EXPLICIT_HUMAN_GRANT_ACCEPTED",
            action_id=action_id,
            grant_id=grant.grant_id,
        )
