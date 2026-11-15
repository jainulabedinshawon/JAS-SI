"""Persistent task worker runtime with fail-closed authorization.

The runtime owns queue polling and lifecycle coordination. Concrete model and
tool handlers must be explicitly registered by the host application; task
payloads cannot dynamically import code or select arbitrary executors.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import Event, Thread
from typing import Callable, Mapping

from jas_si_agent.authorization import (
    GRANT_REQUIRED_ACTIONS,
    ActionRequest,
    AuthorizationGate,
    AuthorizationGrant,
)
from jas_si_agent.agent_task_worker_store import (
    AgentTaskLease,
    AgentTaskWorkerStoreError,
    PostgresAgentTaskWorkerStore,
)

TaskExecutor = Callable[[AgentTaskLease, Event], Mapping[str, object]]
ResourceResolver = Callable[[AgentTaskLease], str]
GrantResolver = Callable[[AgentTaskLease], AuthorizationGrant | None]
SimulationResolver = Callable[[AgentTaskLease], "SimulationResult"]


@dataclass(frozen=True)
class SimulationResult:
    """Host-produced pre-action simulation summary; never proof of real outcome."""
    proceed: bool
    summary: str


@dataclass(frozen=True)
class TaskHandler:
    """Host-registered capability for one exact task type."""
    task_type: str
    action_type: str
    resource_for: ResourceResolver
    execute: TaskExecutor
    grant_for: GrantResolver | None = None
    simulate: SimulationResolver | None = None


@dataclass(frozen=True)
class WorkerOutcome:
    """Local outcome of one polling iteration; not a verified task result."""
    state: str
    task_id: str | None = None
    detail: str | None = None


class AgentTaskWorker:
    """Claim, authorize, execute and report one task at a time.

    Worker reports are not verified results. The database transitions reports
    to awaiting_verification; only a trusted verifier may finalize them.
    """

    def __init__(
        self,
        *,
        store: PostgresAgentTaskWorkerStore,
        handlers: Mapping[str, TaskHandler],
        authorization_gate: AuthorizationGate | None = None,
        lease_seconds: int = 60,
        heartbeat_interval_seconds: float | None = None,
    ) -> None:
        # Depend on the narrow store contract, not a concrete connection
        # class, so deterministic in-memory stores can exercise the lifecycle.
        required_store_methods = ("claim", "renew", "acknowledge_cancel", "report", "fail")
        if any(not callable(getattr(store, name, None)) for name in required_store_methods):
            raise TypeError("store does not implement the agent task worker store contract")
        if not isinstance(handlers, Mapping) or not handlers:
            raise ValueError("At least one explicitly registered task handler is required")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int):
            raise ValueError("lease_seconds must be an integer")
        if not 15 <= lease_seconds <= 300:
            raise ValueError("lease_seconds must be between 15 and 300")

        validated: dict[str, TaskHandler] = {}
        for key, handler in handlers.items():
            if (
                not isinstance(handler, TaskHandler)
                or not isinstance(key, str)
                or not key
                or key != handler.task_type
                or not isinstance(handler.action_type, str)
                or not handler.action_type
                or not callable(handler.resource_for)
                or not callable(handler.execute)
                or (handler.grant_for is not None and not callable(handler.grant_for))
                or (handler.simulate is not None and not callable(handler.simulate))
            ):
                raise ValueError("Invalid task handler registration")
            validated[key] = handler

        heartbeat = max(1.0, lease_seconds / 3) if heartbeat_interval_seconds is None else heartbeat_interval_seconds
        if (
            isinstance(heartbeat, bool)
            or not isinstance(heartbeat, (int, float))
            or heartbeat <= 0
            or heartbeat >= lease_seconds
        ):
            raise ValueError("heartbeat interval must be positive and shorter than the lease")

        self._store = store
        self._handlers = validated
        self._gate = authorization_gate or AuthorizationGate()
        self._lease_seconds = lease_seconds
        self._heartbeat_interval = float(heartbeat)

    def _heartbeat(
        self,
        lease: AgentTaskLease,
        stop: Event,
        cancelled: Event,
        lease_lost: Event,
        renewal_rejected: Event,
    ) -> None:
        while not stop.wait(self._heartbeat_interval):
            try:
                renewed = self._store.renew(
                    task_id=lease.task_id,
                    lease_fence=lease.lease_fence,
                    lease_seconds=self._lease_seconds,
                )
            except Exception:
                lease_lost.set()
                cancelled.set()
                return
            if renewed:
                continue
            # A false renewal may mean cancellation or a stale lease. Signal
            # cooperative shutdown first; never acknowledge cancellation while
            # the task handler may still be performing side effects.
            renewal_rejected.set()
            cancelled.set()
            return

    def run_once(self) -> WorkerOutcome:
        """Claim and process at most one task. Empty queues return immediately."""
        lease = self._store.claim(lease_seconds=self._lease_seconds)
        if lease is None:
            return WorkerOutcome("idle")

        task_id = str(lease.task_id)
        handler = self._handlers.get(lease.task_type)
        if handler is None:
            state = self._store.fail(
                task_id=lease.task_id,
                lease_fence=lease.lease_fence,
                error_code="UNSUPPORTED_TASK_TYPE",
            )
            return WorkerOutcome("failed", task_id, state or "lease_not_owned")

        cancelled = Event()
        heartbeat_stop = Event()
        lease_lost = Event()
        renewal_rejected = Event()
        heartbeat = Thread(
            target=self._heartbeat,
            args=(lease, heartbeat_stop, cancelled, lease_lost, renewal_rejected),
            name=f"jas-si-task-lease-{task_id}",
            daemon=True,
        )
        heartbeat.start()

        result: Mapping[str, object] | None = None
        failure_code: str | None = None
        try:
            grant = handler.grant_for(lease) if handler.grant_for else None
            decision = self._gate.evaluate(
                ActionRequest(
                    action_id=task_id,
                    action_type=handler.action_type,
                    resource=handler.resource_for(lease),
                ),
                grant=grant,
            )
            if decision.allowed is not True:
                failure_code = "ACTION_NOT_AUTHORIZED"
            elif handler.action_type in GRANT_REQUIRED_ACTIONS and handler.simulate is None:
                # Consequential actions must have an explicit host simulation
                # contract. A missing simulator is a hard stop, never a bypass.
                failure_code = "SIMULATION_REQUIRED"
            else:
                simulation: SimulationResult | None = None
                if handler.simulate is not None:
                    simulation = handler.simulate(lease)
                    if (
                        not isinstance(simulation, SimulationResult)
                        or not isinstance(simulation.proceed, bool)
                        or not isinstance(simulation.summary, str)
                        or not simulation.summary.strip()
                        or len(simulation.summary) > 500
                    ):
                        failure_code = "SIMULATION_INVALID"
                    elif simulation.proceed is not True:
                        failure_code = "SIMULATION_REJECTED"
                if failure_code is None:
                    result = handler.execute(lease, cancelled)
                    if not isinstance(result, Mapping):
                        failure_code = "INVALID_HANDLER_RESULT"
                        result = None
                    elif simulation is not None:
                        if "jas_si_pre_action_simulation" in result:
                            failure_code = "RESERVED_RESULT_FIELD_COLLISION"
                            result = None
                        else:
                            result = {
                                **dict(result),
                                "jas_si_pre_action_simulation": {
                                    "proceed": simulation.proceed,
                                    "summary": simulation.summary,
                                },
                            }
        except Exception:
            failure_code = "HANDLER_EXECUTION_ERROR"
        finally:
            heartbeat_stop.set()
            heartbeat.join()

        if renewal_rejected.is_set() and not lease_lost.is_set():
            # The executor has now returned, so a successful DB acknowledgement
            # means its cooperative stop was observed before terminal cancel.
            try:
                acknowledged = self._store.acknowledge_cancel(
                    task_id=lease.task_id,
                    lease_fence=lease.lease_fence,
                )
            except Exception:
                acknowledged = False
            if acknowledged:
                return WorkerOutcome("cancelled", task_id, "cancellation_acknowledged")
            lease_lost.set()
        if lease_lost.is_set():
            return WorkerOutcome("lease_lost", task_id, "lease_ownership_not_confirmed")
        if cancelled.is_set():
            return WorkerOutcome("cancelled", task_id, "execution_stopped")

        if failure_code is not None:
            state = self._store.fail(
                task_id=lease.task_id,
                lease_fence=lease.lease_fence,
                error_code=failure_code,
            )
            return WorkerOutcome("failed", task_id, state or "lease_not_owned")

        if result is None:
            return WorkerOutcome("failed", task_id, "missing_handler_result")

        reported = self._store.report(
            task_id=lease.task_id,
            lease_fence=lease.lease_fence,
            result_payload=result,
        )
        if not reported:
            # Cancellation can race with the final heartbeat after the handler
            # returns. The database rejects reports for cancel_requested tasks;
            # acknowledge only if the current fencing token still owns that
            # cancellation. A stale worker can never turn a cancellation into
            # a report or terminal state.
            try:
                acknowledged = self._store.acknowledge_cancel(
                    task_id=lease.task_id,
                    lease_fence=lease.lease_fence,
                )
            except Exception:
                acknowledged = False
            if acknowledged:
                return WorkerOutcome(
                    "cancelled", task_id, "cancellation_acknowledged_after_report_rejection"
                )
            return WorkerOutcome("lease_lost", task_id, "report_rejected_for_stale_lease")
        return WorkerOutcome("awaiting_verification", task_id)

    def run_forever(
        self,
        stop_event: Event,
        *,
        idle_wait_seconds: float = 1.0,
        error_wait_seconds: float = 2.0,
    ) -> None:
        """Poll until shutdown; transient store errors use bounded fixed backoff."""
        if not isinstance(stop_event, Event):
            raise TypeError("stop_event must be a threading.Event")
        for name, value in (
            ("idle_wait_seconds", idle_wait_seconds),
            ("error_wait_seconds", error_wait_seconds),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"{name} must be positive")
        while not stop_event.is_set():
            try:
                outcome = self.run_once()
            except AgentTaskWorkerStoreError:
                # Do not hot-loop on database outages. Host supervision still
                # owns process restart, liveness and alerting.
                stop_event.wait(float(error_wait_seconds))
                continue
            if outcome.state == "idle":
                stop_event.wait(float(idle_wait_seconds))


__all__ = ["AgentTaskWorker", "SimulationResult", "TaskHandler", "WorkerOutcome"]
