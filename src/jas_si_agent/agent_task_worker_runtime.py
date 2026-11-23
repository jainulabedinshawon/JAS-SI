"""Explicit host composition for the tenant-bound GitHub read worker.

This factory does not start a background process or read credentials from
ambient environment variables. Deployment code must inject a dedicated
PostgreSQL worker DSN and a trusted GitHub App installation provider.
"""
from __future__ import annotations

from uuid import UUID

from jas_si_agent.agent_task_worker import AgentTaskWorker
from jas_si_agent.agent_task_worker_store import PostgresAgentTaskWorkerStore
from jas_si_agent.github_installations import TenantGitHubInstallationProvider
from jas_si_agent.github_repository_read import build_github_repository_read_handler


def build_github_repository_worker(
    *,
    worker_dsn: str,
    worker_id: UUID,
    credential_provider: TenantGitHubInstallationProvider,
    lease_seconds: int = 60,
) -> AgentTaskWorker:
    """Compose a least-privilege worker with exactly one read-only handler.

    The DSN must belong to the dedicated database worker role, not the public
    API role. The credential provider must be a trusted host adapter backed by
    the tenant's GitHub App installation records. This function only builds
    the worker; a supervisor must explicitly start and monitor its lifecycle.
    """
    if not isinstance(worker_dsn, str) or not worker_dsn.strip():
        raise ValueError("A dedicated worker PostgreSQL DSN is required")
    if not isinstance(worker_id, UUID):
        raise ValueError("worker_id must be a UUID")
    if credential_provider is None or not callable(getattr(credential_provider, "resolve", None)):
        raise ValueError("A trusted tenant GitHub credential provider is required")

    handler = build_github_repository_read_handler(credential_provider)
    store = PostgresAgentTaskWorkerStore(worker_dsn, worker_id)
    return AgentTaskWorker(
        store=store,
        handlers={handler.task_type: handler},
        lease_seconds=lease_seconds,
    )


__all__ = ["build_github_repository_worker"]
