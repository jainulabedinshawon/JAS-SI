
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .authorization_gate import AuthorizationDecision, AuthorizationGate


@dataclass(frozen=True)
class ExecutionResult:
    allowed: bool
    action_executed: bool
    reason: str
    audit_event: str
    output: object | None = None


class ProtectedExecutor:
    """
    Development-only execution boundary.

    The protected callable runs only after the trusted authorization
    gate returns an allowed decision. Denied actions are never invoked.
    """

    def __init__(self, gate: AuthorizationGate | None = None) -> None:
        self._gate = gate if gate is not None else AuthorizationGate()

    def execute(
        self,
        *,
        requested_action: str,
        requested_scope: str,
        authorization_state: str,
        granted_actions: tuple[str, ...],
        granted_scope: str,
        action: Callable[[], object],
        untrusted_instruction: str | None = None,
    ) -> ExecutionResult:
        if not callable(action):
            raise TypeError("action must be callable")

        decision: AuthorizationDecision = self._gate.evaluate(
            requested_action=requested_action,
            requested_scope=requested_scope,
            authorization_state=authorization_state,
            granted_actions=granted_actions,
            granted_scope=granted_scope,
            untrusted_instruction=untrusted_instruction,
        )

        if not decision.allowed:
            return ExecutionResult(
                allowed=False,
                action_executed=False,
                reason=decision.reason,
                audit_event=decision.audit_event,
            )

        # The protected action is invoked only after authorization passes.
        output = action()

        return ExecutionResult(
            allowed=True,
            action_executed=True,
            reason="AUTHORIZED",
            audit_event=decision.audit_event,
            output=output,
        )
