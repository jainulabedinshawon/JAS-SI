
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: str
    requested_action: str
    requested_scope: str
    authorization_state: str
    audit_event: str


class AuthorizationGate:
    """
    Development-only authorization gate.

    Untrusted instructions cannot grant authorization.
    Only the trusted authorization state, action grant,
    and exact scope match determine the decision.
    """

    def evaluate(
        self,
        *,
        requested_action: str,
        requested_scope: str,
        authorization_state: str,
        granted_actions: tuple[str, ...],
        granted_scope: str,
        untrusted_instruction: str | None = None,
    ) -> AuthorizationDecision:
        fields = {
            "requested_action": requested_action,
            "requested_scope": requested_scope,
            "authorization_state": authorization_state,
            "granted_scope": granted_scope,
        }

        for name, value in fields.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")

        if not isinstance(granted_actions, tuple):
            raise TypeError("granted_actions must be a tuple")

        if any(
            not isinstance(action, str) or not action.strip()
            for action in granted_actions
        ):
            raise ValueError(
                "granted_actions must contain non-empty strings"
            )

        # Untrusted content is deliberately not an authorization source.
        # Its presence must never override the trusted policy.
        del untrusted_instruction

        if authorization_state != "GRANTED":
            return self._decision(
                False,
                "AUTHORIZATION_NOT_GRANTED",
                requested_action,
                requested_scope,
                authorization_state,
            )

        if requested_action not in granted_actions:
            return self._decision(
                False,
                "ACTION_NOT_GRANTED",
                requested_action,
                requested_scope,
                authorization_state,
            )

        if requested_scope != granted_scope:
            return self._decision(
                False,
                "SCOPE_MISMATCH",
                requested_action,
                requested_scope,
                authorization_state,
            )

        return self._decision(
            True,
            "AUTHORIZED",
            requested_action,
            requested_scope,
            authorization_state,
        )

    @staticmethod
    def _decision(
        allowed: bool,
        reason: str,
        action: str,
        scope: str,
        state: str,
    ) -> AuthorizationDecision:
        return AuthorizationDecision(
            allowed=allowed,
            reason=reason,
            requested_action=action,
            requested_scope=scope,
            authorization_state=state,
            audit_event=(
                f"authorization_decision={reason};"
                f"action={action};"
                f"scope={scope};"
                f"state={state};"
                f"allowed={str(allowed).lower()}"
            ),
        )
