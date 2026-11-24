"""Small, restart-friendly host process for the JAS-SI read-only task worker.

Credentials are injected by the deployment platform. This module never
provisions credentials, starts the API server, or enables task submission.
"""
from __future__ import annotations

import logging
import os
import signal
import threading
from uuid import UUID

from jas_si_agent.agent_host_health import AgentHostHealthServer, AgentHostHealthState
from jas_si_agent.agent_task_host_preflight import (
    AgentHostPreflightError,
    verify_agent_host_database_access,
)
from jas_si_agent.agent_task_worker import AgentTaskWorker
from jas_si_agent.agent_task_worker_runtime import build_github_repository_worker
from jas_si_agent.github_capability_client import GitHubCapabilityBrokerClient
from jas_si_agent.github_capability_evidence import build_broker_github_repository_worker

_LOG = logging.getLogger("jas_si_agent.worker")

class _PublicRepositoryOnlyProvider:
    """Fail-closed provider: private installation credentials are not configured."""

    def resolve(self, *, tenant_id: UUID, repository: str):
        # Returning None deliberately limits this host to public repositories.
        return None


def run_worker_loop(
    worker: AgentTaskWorker,
    *,
    stop_event: threading.Event,
    poll_interval_seconds: float = 2.0,
    health_state: AgentHostHealthState | None = None,
) -> None:
    """Poll one task at a time, throttle every iteration, and stop cooperatively."""
    if (
        isinstance(poll_interval_seconds, bool)
        or not isinstance(poll_interval_seconds, (int, float))
        or not 0.1 <= poll_interval_seconds <= 60
    ):
        raise ValueError("poll_interval_seconds must be between 0.1 and 60")

    while not stop_event.is_set():
        try:
            outcome = worker.run_once()
            if health_state is not None:
                health_state.mark_success()
            _LOG.info("worker iteration state=%s", outcome.state)
        except Exception:
            if health_state is not None:
                health_state.mark_failure()
            # Do not log exception text: database/driver errors can contain
            # connection details. The process remains observable without
            # risking DSN or credential disclosure.
            _LOG.error("worker iteration failed; retrying after poll interval")
        if stop_event.wait(float(poll_interval_seconds)):
            break


def main() -> None:
    """Deployment entry point; all secrets must be injected at runtime."""
    dsn = os.environ.get("JAS_SI_AGENT_WORKER_DSN", "").strip()
    worker_id_raw = os.environ.get("JAS_SI_AGENT_WORKER_ID", "").strip()
    poll_raw = os.environ.get("JAS_SI_AGENT_WORKER_POLL_SECONDS", "2").strip()
    health_port_raw = os.environ.get("JAS_SI_AGENT_HEALTH_PORT", "8000").strip()
    if not dsn or not worker_id_raw:
        raise SystemExit(
            "JAS_SI_AGENT_WORKER_DSN and JAS_SI_AGENT_WORKER_ID are required"
        )
    try:
        worker_id = UUID(worker_id_raw)
        poll_interval = float(poll_raw)
        health_port = int(health_port_raw)
    except (ValueError, TypeError):
        raise SystemExit("Worker identity or poll interval is invalid") from None
    if not 0.1 <= poll_interval <= 60:
        raise SystemExit("JAS_SI_AGENT_WORKER_POLL_SECONDS must be between 0.1 and 60")
    if not 1 <= health_port <= 65535:
        raise SystemExit("JAS_SI_AGENT_HEALTH_PORT must be between 1 and 65535")

    try:
        verify_agent_host_database_access(
            dsn,
            capability_role="jas_si_agent_worker",
            expected_login=os.environ.get("JAS_SI_AGENT_WORKER_DB_LOGIN", "jas_si_agent_worker_login").strip(),
            required_functions=(
                "public.jas_si_agent_task_claim(uuid,integer)",
                "public.jas_si_agent_task_renew(uuid,uuid,bigint,integer)",
                "public.jas_si_agent_task_ack_cancel(uuid,uuid,bigint)",
                "public.jas_si_agent_task_report(uuid,uuid,bigint,jsonb)",
                "public.jas_si_agent_task_fail(uuid,uuid,bigint,text,integer)",
            ),
        )
    except AgentHostPreflightError:
        raise SystemExit("Worker database readiness preflight failed") from None

    # GitHub App signing material remains Broker-only. Workloads may use
    # mTLS-mounted client credentials, never installation tokens or App keys.
    if any(os.environ.get(name, "").strip() for name in (
        "JAS_SI_GITHUB_APP_ID",
        "GITHUB_APP_ID",
        "JAS_SI_GITHUB_APP_PRIVATE_KEY_B64",
        "GITHUB_APP_PRIVATE_KEY_PATH",
    )):
        raise SystemExit(
            "GitHub App signing configuration is restricted to the isolated reconciler; Broker signing material remains Broker-only"
        )
    broker_enabled = os.environ.get("JAS_SI_GITHUB_CAPABILITY_BROKER_ENABLED", "").strip().lower()
    broker_client = None
    if broker_enabled == "true":
        try:
            broker_client = GitHubCapabilityBrokerClient.from_env()
            worker = build_broker_github_repository_worker(
                worker_dsn=dsn,
                worker_id=worker_id,
                broker_client=broker_client,
            )
        except (TypeError, ValueError):
            raise SystemExit("Worker GitHub capability Broker mTLS configuration is invalid") from None
    elif broker_enabled in ("", "false"):
        credential_provider = _PublicRepositoryOnlyProvider()
        worker = build_github_repository_worker(
            worker_dsn=dsn,
            worker_id=worker_id,
            credential_provider=credential_provider,
        )
    else:
        raise SystemExit("JAS_SI_GITHUB_CAPABILITY_BROKER_ENABLED must be true or false")
    stop_event = threading.Event()

    def request_stop(_signum, _frame) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    health_state = AgentHostHealthState(max_staleness_seconds=max(30.0, poll_interval * 5))
    health_server = AgentHostHealthServer(health_state, port=health_port)
    health_server.start()
    _LOG.info("JAS-SI read-only worker started; database preflight passed; awaiting first successful poll")
    try:
        run_worker_loop(
            worker,
            stop_event=stop_event,
            poll_interval_seconds=poll_interval,
            health_state=health_state,
        )
    finally:
        health_server.close()
        if broker_client is not None:
            broker_client.close()
    _LOG.info("JAS-SI read-only worker stopped")


if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())
    main()
