"""Worker and independent-verifier adapters for the mTLS GitHub Broker.

The Worker and Verifier receive content/integrity only. The Broker remains the
only component holding GitHub App signing material or installation tokens.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from threading import Event
from typing import Mapping
from uuid import UUID

from jas_si_agent.agent_task_worker import TaskHandler, TenantScopedResource
from jas_si_agent.agent_task_worker_store import AgentTaskLease
from jas_si_agent.github_capability_client import GitHubCapabilityBrokerClient
from jas_si_agent.github_task_verifier import (
    CollectedGitHubEvidence,
    PersistedTask,
)
from jas_si_agent.verify_router import (
    GitHubEvidenceRequest,
    _validate_request,
)

_TASK_TYPE = "github.read_repository"


def _request_for(lease: AgentTaskLease) -> GitHubEvidenceRequest:
    payload = lease.input_payload
    if not isinstance(payload, Mapping) or set(payload) != {"repository", "commit_sha", "paths"}:
        raise ValueError("GitHub repository read task input fields are invalid")
    try:
        request = GitHubEvidenceRequest(**dict(payload))
        _validate_request(request)
    except Exception:
        raise ValueError("GitHub repository read task input is invalid") from None
    return request


def _file_evidence(client, *, task_id, repository, commit_sha, paths, role, lease_fence=None, verifier_claim_token=None):
    """Read each allowlisted path and independently recompute its Git blob hash."""
    files = []
    for path in paths:
        item = client.read_file(
            task_id=task_id,
            repository=repository,
            commit_sha=commit_sha,
            path=path,
            role=role,
            lease_fence=lease_fence,
            verifier_claim_token=verifier_claim_token,
        )
        content = item.get("content")
        if not isinstance(content, bytes):
            raise ValueError("Broker client returned invalid file content")
        files.append({
            "path": path,
            "blob_sha": item["blob_sha"],
            "sha256": item["sha256"],
            "size_bytes": len(content),
            "integrity": "VERIFIED",
        })
    return tuple(files)


def _content_digest(repository: str, commit_sha: str, tree_sha: str, files) -> str:
    canonical = "|".join([
        repository,
        commit_sha,
        tree_sha,
        *[
            f"{item['path']}:{item['blob_sha']}:{item['sha256']}"
            for item in files
        ],
    ]).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_broker_github_repository_read_handler(
    broker_client: GitHubCapabilityBrokerClient,
) -> TaskHandler:
    """Build a Worker handler that can read only through its current lease fence."""
    if broker_client is None or not callable(getattr(broker_client, "read_file", None)) or not callable(
        getattr(broker_client, "read_commit", None)
    ):
        raise ValueError("A trusted GitHub capability Broker client is required")

    def resource_for(lease: AgentTaskLease) -> TenantScopedResource:
        request = _request_for(lease)
        return TenantScopedResource(tenant_id=lease.tenant_id, resource=request.repository.casefold())

    def execute(lease: AgentTaskLease, cancelled: Event) -> Mapping[str, object]:
        if cancelled.is_set():
            raise RuntimeError("Task cancelled before GitHub Broker read")
        request = _request_for(lease)
        commit = broker_client.read_commit(
            task_id=lease.task_id,
            repository=request.repository,
            commit_sha=request.commit_sha,
            role="worker",
            lease_fence=lease.lease_fence,
        )
        if cancelled.is_set():
            raise RuntimeError("Task cancelled before GitHub file reads")
        if commit.get("tree_sha") is None:
            raise ValueError("Broker commit metadata is incomplete")
        files = _file_evidence(
            broker_client,
            task_id=lease.task_id,
            repository=request.repository,
            commit_sha=request.commit_sha,
            paths=tuple(request.paths),
            role="worker",
            lease_fence=lease.lease_fence,
        )
        if cancelled.is_set():
            raise RuntimeError("Task cancelled during GitHub file reads")
        evidence = {
            "service": "JAS-SI Verify",
            "status": "EVIDENCE_INTEGRITY_VERIFIED",
            "verification_scope": "github_commit_and_file_integrity",
            "access_mode": "task_scoped_github_capability_broker",
            "repository": request.repository,
            "commit_sha": request.commit_sha,
            "tree_sha": commit["tree_sha"],
            "files_verified": len(files),
            "files": [dict(item) for item in files],
            "read_only": True,
            "semantic_truth_verified": False,
        }
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


class BrokerGitHubEvidenceCollector:
    """Independent Verifier collector requiring a persisted verifier claim token."""

    def __init__(self, *, collector_id: str, broker_client: GitHubCapabilityBrokerClient) -> None:
        if not isinstance(collector_id, str) or not collector_id.strip() or len(collector_id) > 128:
            raise ValueError("A stable collector identity is required")
        if broker_client is None or not callable(getattr(broker_client, "read_file", None)) or not callable(
            getattr(broker_client, "read_commit", None)
        ):
            raise ValueError("A trusted GitHub capability Broker client is required")
        self._collector_id = collector_id
        self._broker_client = broker_client

    def collect(self, *, tenant_id: UUID, repository: str, commit_sha: str, paths: tuple[str, ...]):
        # The legacy protocol has no task ID or claim token. Never silently
        # downgrade a private-repository verification to an unbound request.
        raise RuntimeError("A persisted task and verifier claim are required for Broker evidence")

    def collect_for_task(
        self,
        *,
        task: PersistedTask,
        repository: str,
        commit_sha: str,
        paths: tuple[str, ...],
    ) -> CollectedGitHubEvidence:
        if (
            not isinstance(task, PersistedTask)
            or not isinstance(task.task_id, UUID)
            or not isinstance(task.tenant_id, UUID)
            or not isinstance(task.verifier_claim_token, UUID)
        ):
            raise ValueError("A persisted task with the current verifier claim is required")
        commit = self._broker_client.read_commit(
            task_id=task.task_id,
            repository=repository,
            commit_sha=commit_sha,
            role="verifier",
            verifier_claim_token=task.verifier_claim_token,
        )
        tree_sha = commit.get("tree_sha")
        if not isinstance(tree_sha, str):
            raise ValueError("Broker commit metadata is incomplete")
        files = _file_evidence(
            self._broker_client,
            task_id=task.task_id,
            repository=repository,
            commit_sha=commit_sha,
            paths=paths,
            role="verifier",
            verifier_claim_token=task.verifier_claim_token,
        )
        return CollectedGitHubEvidence(
            collector_id=self._collector_id,
            collected_at=datetime.now(timezone.utc),
            repository=repository,
            commit_sha=commit_sha,
            tree_sha=tree_sha,
            files=files,
            content_digest=_content_digest(repository, commit_sha, tree_sha, files),
        )


__all__ = [
    "BrokerGitHubEvidenceCollector",
    "build_broker_github_repository_read_handler",
]
