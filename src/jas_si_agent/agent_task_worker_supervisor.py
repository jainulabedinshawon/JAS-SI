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

from jas_si_agent.agent_task_host_preflight import (
    AgentHostPreflightError,
    verify_agent_host_database_access,
)
from jas_si_agent.agent_task_worker import AgentTaskWorker
from jas_si_agent.agent_task_worker_runtime import build_github_repository_worker

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
            _LOG.info("worker iteration state=%s", outcome.state)
        except Exception:
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
    if not dsn or not worker_id_raw:
        raise SystemExit(
            "JAS_SI_AGENT_WORKER_DSN and JAS_SI_AGENT_WORKER_ID are required"
        )
    try:
        worker_id = UUID(worker_id_raw)
        poll_interval = float(poll_raw)
    except (ValueError, TypeError):
        raise SystemExit("Worker identity or poll interval is invalid") from None
    if not 0.1 <= poll_interval <= 60:
        raise SystemExit("JAS_SI_AGENT_WORKER_POLL_SECONDS must be between 0.1 and 60")

    try:
        verify_agent_host_database_access(
            dsn,
            capability_role="jas_si_agent_worker",
            expected_login="jas_si_agent_worker_login",
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

    worker = build_github_repository_worker(
        worker_dsn=dsn,
        worker_id=worker_id,
        credential_provider=_PublicRepositoryOnlyProvider(),
    )
    stop_event = threading.Event()

    def request_stop(_signum, _frame) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    _LOG.info("JAS-SI read-only worker started; database preflight passed")
    run_worker_loop(
        worker,
        stop_event=stop_event,
        poll_interval_seconds=poll_interval,
    )
    _LOG.info("JAS-SI read-only worker stopped")


if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())
    main()
