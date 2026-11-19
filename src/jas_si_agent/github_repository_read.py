"""Read-only, tenant-bound GitHub repository task handler.

This module supplies a concrete capability to a host-registered AgentTaskWorker.
It deliberately reports integrity evidence only; semantic success must still be
established by a separate trusted verifier after the worker report is stored.
"""
from __future__ import annotations

from threading import Event
from typing import Mapping

from jas_si_agent.agent_task_worker import TaskHandler, TenantScopedResource
from jas_si_agent.agent_task_worker_store import AgentTaskLease
from jas_si_agent.github_installations import (
    TenantGitHubInstallationProvider,
    resolve_tenant_github_credential,
)
from jas_si_agent.verify_router import (
    GitHubEvidenceRequest,
    _validate_request,
    _verify_github_evidence,
)

_TASK_TYPE = "github.read_repository"


def _request_for(lease: AgentTaskLease) -> GitHubEvidenceRequest:
    payload = lease.input_payload
    if not isinstance(payload, Mapping):
        raise ValueError("GitHub repository read task input must be an object")
    if set(payload) != {"repository", "commit_sha", "paths"}:
        raise ValueError("GitHub repository read task input fields are invalid")
    try:
        request = GitHubEvidenceRequest(**dict(payload))
        _validate_request(request)
    except Exception:
        raise ValueError("GitHub repository read task input is invalid") from None
    return request


def build_github_repository_read_handler(
    credential_provider: TenantGitHubInstallationProvider,
) -> TaskHandler:
    """Build a read-only worker handler using a trusted tenant credential provider.

    A provider result is validated for tenant, repository and token expiry.
    Returning None permits public-only GitHub access; provider errors and
    mismatched credentials fail closed. The provider itself must be supplied
    by the host and must never trust tenant IDs from task payloads.
    """
    if credential_provider is None or not callable(getattr(credential_provider, "resolve", None)):
        raise ValueError("A trusted tenant GitHub credential provider is required")

    def resource_for(lease: AgentTaskLease) -> TenantScopedResource:
        request = _request_for(lease)
        return TenantScopedResource(
            tenant_id=lease.tenant_id,
            resource=request.repository.casefold(),
        )

    def execute(lease: AgentTaskLease, cancelled: Event) -> Mapping[str, object]:
        if cancelled.is_set():
            raise RuntimeError("Task cancelled before GitHub read")
        request = _request_for(lease)
        credential = resolve_tenant_github_credential(
            credential_provider,
            tenant_id=lease.tenant_id,
            repository=request.repository,
        )
        if cancelled.is_set():
            raise RuntimeError("Task cancelled before GitHub request")
        access_token = credential.access_token if credential is not None else None
        access_mode = (
            "tenant_github_app_installation"
            if credential is not None
            else "public_repository_only"
        )
        evidence = _verify_github_evidence(
            request,
            access_token=access_token,
            access_mode=access_mode,
        )
        if cancelled.is_set():
            raise RuntimeError("Task cancelled during GitHub read")
        return {
            "task_type": _TASK_TYPE,
            "repository": request.repository,
            "commit_sha": request.commit_sha,
            "evidence_integrity": evidence,
            "semantic_truth_verified": False,
        }

    return TaskHandler(
        task_type=_TASK_TYPE,
        action_type="read_repository",
        resource_for=resource_for,
        execute=execute,
    )


__all__ = ["build_github_repository_read_handler"]
