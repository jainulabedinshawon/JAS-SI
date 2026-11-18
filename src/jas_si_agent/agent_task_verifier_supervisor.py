"""Supervised host process for JAS-SI's independent task verifier.

The verifier uses a dedicated database login and independently collects
GitHub evidence. Private-repository access is enabled only when a trusted
Tenant-bound GitHub App provider is configured through deployment secrets.
"""
from __future__ import annotations

import logging
import os
import signal
import threading

from jas_si_agent.agent_host_health import AgentHostHealthServer, AgentHostHealthState
from jas_si_agent.agent_task_host_preflight import (
    AgentHostPreflightError,
    verify_agent_host_database_access,
)
from jas_si_agent.agent_task_verifier import build_github_repository_verifier
from jas_si_agent.github_app_tokens import (
    build_github_app_tenant_credential_provider,
)

_LOG = logging.getLogger("jas_si_agent.verifier")

class _PublicRepositoryOnlyProvider:
    """Fail-closed provider: no private installation credentials are configured."""

    def resolve(self, *, tenant_id, repository):
        return None


def run_verifier_loop(
    verifier,
    *,
    stop_event: threading.Event,
    poll_interval_seconds: float = 2.0,
    health_state: AgentHostHealthState | None = None,
) -> None:
    """Run bounded verification batches with throttling and cooperative shutdown."""
    if (
        isinstance(poll_interval_seconds, bool)
        or not isinstance(poll_interval_seconds, (int, float))
        or not 0.1 <= poll_interval_seconds <= 60
    ):
        raise ValueError("poll_interval_seconds must be between 0.1 and 60")

    while not stop_event.is_set():
        try:
            outcome = verifier.run_once()
            if health_state is not None:
                health_state.mark_success()
            _LOG.info(
                "verifier iteration scanned=%s finalized=%s inconclusive=%s lost_race=%s",
                outcome.scanned,
                outcome.finalized,
                outcome.inconclusive,
                outcome.lost_finalization_race,
            )
        except Exception:
            if health_state is not None:
                health_state.mark_failure()
            # Driver/provider exception text can contain DSNs or credentials.
            _LOG.error("verifier iteration failed; retrying after poll interval")
        if stop_event.wait(float(poll_interval_seconds)):
            break


def main() -> None:
    """Deployment entry point; inject the dedicated Staging DSN as a secret."""
    dsn = os.environ.get("JAS_SI_AGENT_VERIFIER_DSN", "").strip()
    poll_raw = os.environ.get("JAS_SI_AGENT_VERIFIER_POLL_SECONDS", "2").strip()
    batch_raw = os.environ.get("JAS_SI_AGENT_VERIFIER_BATCH_SIZE", "10").strip()
    health_port_raw = os.environ.get("JAS_SI_AGENT_HEALTH_PORT", "8000").strip()
    collector_id = os.environ.get(
        "JAS_SI_AGENT_VERIFIER_COLLECTOR_ID", "jas-si-staging-verifier-v1"
    ).strip()

    if not dsn:
        raise SystemExit("JAS_SI_AGENT_VERIFIER_DSN is required")
    if not collector_id or len(collector_id) > 128:
        raise SystemExit("JAS_SI_AGENT_VERIFIER_COLLECTOR_ID is invalid")
    try:
        poll_interval = float(poll_raw)
        batch_size = int(batch_raw)
        health_port = int(health_port_raw)
    except (ValueError, TypeError):
        raise SystemExit("Verifier poll interval or batch size is invalid") from None
    if not 0.1 <= poll_interval <= 60:
        raise SystemExit("JAS_SI_AGENT_VERIFIER_POLL_SECONDS must be between 0.1 and 60")
    if not 1 <= batch_size <= 20:
        raise SystemExit("JAS_SI_AGENT_VERIFIER_BATCH_SIZE must be between 1 and 20")
    if not 1 <= health_port <= 65535:
        raise SystemExit("JAS_SI_AGENT_HEALTH_PORT must be between 1 and 65535")

    try:
        verify_agent_host_database_access(
            dsn,
            capability_role="jas_si_agent_verifier",
            expected_login="jas_si_agent_verifier_login",
            required_functions=(
                "public.jas_si_agent_task_verification_claim(integer,integer)",
                "public.jas_si_agent_task_verification_release(uuid,uuid,uuid)",
                "public.jas_si_agent_task_finalize_success(uuid,uuid,uuid,uuid,text,bytea,jsonb,timestamptz)",
            ),
        )
    except AgentHostPreflightError:
        raise SystemExit("Verifier database readiness preflight failed") from None

    app_id_raw = os.environ.get("GITHUB_APP_ID", "").strip()
    private_key_path = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH", "").strip()
    if bool(app_id_raw) != bool(private_key_path):
        raise SystemExit(
            "GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY_PATH must be configured together"
        )
    if app_id_raw:
        try:
            app_id = int(app_id_raw)
            credential_provider = build_github_app_tenant_credential_provider(
                database_dsn=dsn,
                app_id=app_id,
                private_key_path=private_key_path,
            )
        except (ValueError, TypeError):
            raise SystemExit("GitHub App runtime configuration is invalid") from None
    else:
        credential_provider = _PublicRepositoryOnlyProvider()

    verifier = build_github_repository_verifier(
        verifier_dsn=dsn,
        credential_provider=credential_provider,
        collector_id=collector_id,
        batch_size=batch_size,
    )
    stop_event = threading.Event()

    def request_stop(_signum, _frame) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    health_state = AgentHostHealthState(max_staleness_seconds=max(30.0, poll_interval * 5))
    health_server = AgentHostHealthServer(health_state, port=health_port)
    health_server.start()
    _LOG.info("JAS-SI independent verifier started; database preflight passed; awaiting first successful poll")
    try:
        run_verifier_loop(
            verifier,
            stop_event=stop_event,
            poll_interval_seconds=poll_interval,
            health_state=health_state,
        )
    finally:
        health_server.close()
    _LOG.info("JAS-SI independent verifier stopped")


if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())
    main()
