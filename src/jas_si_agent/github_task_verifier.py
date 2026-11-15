"""Independent verification for immutable GitHub repository-read tasks.

The collector performs a fresh GitHub read after the worker report has been
stored. It does not consume the worker's claimed evidence as proof. This
module is intentionally narrow: it can verify successful immutable reads,
but does not infer failure from ambiguous GitHub 404/403 responses.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol
from uuid import UUID

from jas_si_agent.github_installations import (
    GitHubCredentialResolutionError,
    TenantGitHubInstallationProvider,
    resolve_tenant_github_credential,
)
from jas_si_agent.verify_router import (
    GitHubEvidenceRequest,
    _validate_request,
    _verify_github_evidence,
)
from jas_si_agent.verification import VerificationStatus


@dataclass(frozen=True)
class PersistedTask:
    """Task facts loaded by a trusted server-side task repository."""

    task_id: UUID
    tenant_id: UUID
    task_type: str
    input_payload: Mapping[str, Any]


@dataclass(frozen=True)
class WorkerTaskReport:
    """Untrusted worker report persisted before verification."""

    task_id: UUID
    claimed_success: bool
    result_payload: Mapping[str, Any]


@dataclass(frozen=True)
class CollectedGitHubEvidence:
    """Evidence returned directly by the independent collector."""

    collector_id: str
    collected_at: datetime
    repository: str
    commit_sha: str
    tree_sha: str
    files: tuple[Mapping[str, Any], ...]
    content_digest: str


@dataclass(frozen=True)
class TaskVerificationDecision:
    status: VerificationStatus
    reason: str
    task_id: UUID
    evidence: CollectedGitHubEvidence | None = None


class GitHubEvidenceCollector(Protocol):
    def collect(
        self,
        *,
        tenant_id: UUID,
        repository: str,
        commit_sha: str,
        paths: tuple[str, ...],
    ) -> CollectedGitHubEvidence:
        """Fetch evidence independently from GitHub, not from worker output."""


class TenantGitHubEvidenceCollector:
    """GitHub collector using only a trusted tenant installation provider."""

    def __init__(
        self,
        *,
        collector_id: str,
        credential_provider: TenantGitHubInstallationProvider,
    ) -> None:
        if not isinstance(collector_id, str) or not collector_id.strip():
            raise ValueError("A stable collector identity is required")
        if credential_provider is None or not callable(
            getattr(credential_provider, "resolve", None)
        ):
            raise ValueError("A trusted tenant GitHub credential provider is required")
        self._collector_id = collector_id
        self._credential_provider = credential_provider

    def collect(
        self,
        *,
        tenant_id: UUID,
        repository: str,
        commit_sha: str,
        paths: tuple[str, ...],
    ) -> CollectedGitHubEvidence:
        request = GitHubEvidenceRequest(
            repository=repository,
            commit_sha=commit_sha,
            paths=list(paths),
        )
        _validate_request(request)
        credential = resolve_tenant_github_credential(
            self._credential_provider,
            tenant_id=tenant_id,
            repository=repository,
        )
        result = _verify_github_evidence(
            request,
            access_token=credential.access_token if credential is not None else None,
            access_mode=(
                "tenant_github_app_installation"
                if credential is not None
                else "public_repository_only"
            ),
        )
        files = tuple(result.get("files", ()))
        canonical = "|".join(
            [
                str(result.get("repository", "")),
                str(result.get("commit_sha", "")),
                str(result.get("tree_sha", "")),
                *[
                    f"{item.get('path', '')}:{item.get('blob_sha', '')}:{item.get('sha256', '')}"
                    for item in files
                ],
            ]
        ).encode("utf-8")
        return CollectedGitHubEvidence(
            collector_id=self._collector_id,
            collected_at=datetime.now(timezone.utc),
            repository=str(result["repository"]),
            commit_sha=str(result["commit_sha"]),
            tree_sha=str(result["tree_sha"]),
            files=files,
            content_digest=hashlib.sha256(canonical).hexdigest(),
        )


def verify_github_repository_task(
    task: PersistedTask,
    report: WorkerTaskReport,
    *,
    collector: GitHubEvidenceCollector,
) -> TaskVerificationDecision:
    """Verify a persisted read task against a fresh independent GitHub read.

    The task record and report must be loaded server-side and bound to the same
    task and tenant. Worker-supplied evidence fields are never used as proof.
    """
    def inconclusive(reason: str) -> TaskVerificationDecision:
        return TaskVerificationDecision(
            status=VerificationStatus.INCONCLUSIVE,
            reason=reason,
            task_id=task.task_id if isinstance(task, PersistedTask) else UUID(int=0),
        )

    if not isinstance(task, PersistedTask) or not isinstance(report, WorkerTaskReport):
        return inconclusive("INVALID_TASK_OR_REPORT")
    if task.task_id != report.task_id:
        return inconclusive("TASK_REPORT_ID_MISMATCH")
    if task.task_type != "github.read_repository":
        return inconclusive("UNSUPPORTED_TASK_TYPE")
    if not isinstance(task.tenant_id, UUID):
        return inconclusive("INVALID_TENANT_BINDING")
    if not isinstance(task.input_payload, Mapping):
        return inconclusive("INVALID_PERSISTED_TASK_INPUT")

    payload = task.input_payload
    if set(payload) != {"repository", "commit_sha", "paths"}:
        return inconclusive("INVALID_PERSISTED_TASK_INPUT")
    try:
        request = GitHubEvidenceRequest(**dict(payload))
        _validate_request(request)
    except Exception:
        return inconclusive("INVALID_PERSISTED_TASK_INPUT")

    if not isinstance(report.claimed_success, bool) or not isinstance(
        report.result_payload, Mapping
    ):
        return inconclusive("INVALID_WORKER_REPORT")

    # The report must identify the same immutable request. Its evidence is
    # still untrusted until every material field is compared with a fresh read.
    if (
        report.result_payload.get("task_type") != task.task_type
        or report.result_payload.get("repository") != request.repository
        or report.result_payload.get("commit_sha") != request.commit_sha
    ):
        return inconclusive("WORKER_REPORT_REQUEST_MISMATCH")

    if not report.claimed_success:
        return inconclusive("WORKER_REPORTED_FAILURE_REQUIRES_SEPARATE_FAILURE_EVIDENCE")

    try:
        evidence = collector.collect(
            tenant_id=task.tenant_id,
            repository=request.repository,
            commit_sha=request.commit_sha,
            paths=tuple(request.paths),
        )
    except Exception:
        return inconclusive("INDEPENDENT_EVIDENCE_COLLECTION_FAILED")

    if not isinstance(evidence, CollectedGitHubEvidence):
        return inconclusive("INVALID_COLLECTOR_RESULT")
    if (
        not isinstance(evidence.collector_id, str)
        or not evidence.collector_id.strip()
        or not isinstance(evidence.collected_at, datetime)
        or evidence.collected_at.tzinfo is None
        or evidence.collected_at.utcoffset() is None
        or evidence.collected_at > datetime.now(timezone.utc)
        or not isinstance(evidence.repository, str)
        or evidence.repository.casefold() != request.repository.casefold()
        or evidence.commit_sha != request.commit_sha
        or not isinstance(evidence.tree_sha, str)
        or len(evidence.tree_sha) != 40
        or any(char not in "0123456789abcdef" for char in evidence.tree_sha)
        or not isinstance(evidence.content_digest, str)
        or len(evidence.content_digest) != 64
        or any(char not in "0123456789abcdef" for char in evidence.content_digest)
    ):
        return inconclusive("INDEPENDENT_EVIDENCE_BINDING_INVALID")

    if not isinstance(evidence.files, tuple):
        return inconclusive("INDEPENDENT_EVIDENCE_FILE_SET_MISMATCH")
    observed_paths = {
        str(item.get("path")): item
        for item in evidence.files
        if isinstance(item, Mapping)
    }
    if set(observed_paths) != set(request.paths):
        return inconclusive("INDEPENDENT_EVIDENCE_FILE_SET_MISMATCH")
    for path in request.paths:
        item = observed_paths[path]
        if (
            item.get("integrity") != "VERIFIED"
            or not isinstance(item.get("blob_sha"), str)
            or len(item["blob_sha"]) != 40
            or any(char not in "0123456789abcdef" for char in item["blob_sha"])
            or not isinstance(item.get("sha256"), str)
            or len(item["sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in item["sha256"])
        ):
            return inconclusive("INDEPENDENT_FILE_INTEGRITY_NOT_VERIFIED")

    canonical = "|".join(
        [
            evidence.repository,
            evidence.commit_sha,
            evidence.tree_sha,
            *[
                f"{item['path']}:{item['blob_sha']}:{item['sha256']}"
                for item in evidence.files
            ],
        ]
    ).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != evidence.content_digest:
        return inconclusive("INDEPENDENT_EVIDENCE_DIGEST_MISMATCH")

    reported_evidence = report.result_payload.get("evidence_integrity")
    if not isinstance(reported_evidence, Mapping):
        return inconclusive("WORKER_EVIDENCE_REPORT_MISSING")
    if (
        reported_evidence.get("status") != "EVIDENCE_INTEGRITY_VERIFIED"
        or reported_evidence.get("verification_scope")
        != "github_commit_and_file_integrity"
        or reported_evidence.get("repository") != evidence.repository
        or reported_evidence.get("commit_sha") != evidence.commit_sha
        or reported_evidence.get("tree_sha") != evidence.tree_sha
        or reported_evidence.get("files_verified") != len(evidence.files)
        or reported_evidence.get("read_only") is not True
        or reported_evidence.get("semantic_truth_verified") is not False
    ):
        return inconclusive("WORKER_EVIDENCE_REPORT_MISMATCH")

    reported_files = reported_evidence.get("files")
    if not isinstance(reported_files, list) or len(reported_files) != len(evidence.files):
        return inconclusive("WORKER_EVIDENCE_FILE_SET_MISMATCH")
    reported_by_path = {
        str(item.get("path")): item
        for item in reported_files
        if isinstance(item, Mapping)
    }
    if set(reported_by_path) != set(request.paths):
        return inconclusive("WORKER_EVIDENCE_FILE_SET_MISMATCH")
    for path in request.paths:
        reported = reported_by_path[path]
        observed = observed_paths[path]
        if (
            reported.get("integrity") != "VERIFIED"
            or reported.get("blob_sha") != observed.get("blob_sha")
            or reported.get("sha256") != observed.get("sha256")
            or reported.get("size_bytes") != observed.get("size_bytes")
        ):
            return inconclusive("WORKER_EVIDENCE_FILE_MISMATCH")

    return TaskVerificationDecision(
        status=VerificationStatus.VERIFIED_SUCCESS,
        reason="INDEPENDENT_GITHUB_COMMIT_AND_FILE_INTEGRITY_VERIFIED",
        task_id=task.task_id,
        evidence=evidence,
    )


__all__ = [
    "CollectedGitHubEvidence",
    "PersistedTask",
    "TaskVerificationDecision",
    "TenantGitHubEvidenceCollector",
    "WorkerTaskReport",
    "verify_github_repository_task",
]
