"""Bounded orchestration for independent GitHub task verification.

The host calls run_once from a supervised verifier process. This module never
starts a background loop, executes worker tools, or reads ambient credentials.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from jas_si_agent.agent_task_verifier_store import PostgresAgentTaskVerifierStore
from jas_si_agent.github_installations import TenantGitHubInstallationProvider
from jas_si_agent.github_task_verifier import (
    GitHubEvidenceCollector,
    TenantGitHubEvidenceCollector,
    verify_github_repository_task,
)
from jas_si_agent.verification import VerificationStatus


class AgentTaskVerifierStore(Protocol):
    def claim_awaiting_verification(self, *, limit: int = 10, lease_seconds: int = 120):
        ...

    def release_claim(self, *, task) -> bool:
        ...

    def finalize_success(self, *, task, decision) -> bool:
        ...

    def record_inconclusive(self, *, task, reason_code: str) -> str | None:
        ...


@dataclass(frozen=True)
class VerifierBatchResult:
    scanned: int
    finalized: int
    inconclusive: int
    lost_finalization_race: int


class AgentTaskVerifier:
    """Verify a bounded batch and finalize only independently proven successes."""

    def __init__(
        self,
        *,
        store: AgentTaskVerifierStore,
        collector: GitHubEvidenceCollector,
        batch_size: int = 10,
    ) -> None:
        if store is None or not callable(getattr(store, "claim_awaiting_verification", None)):
            raise ValueError("A trusted persisted-task verifier store is required")
        if not callable(getattr(store, "release_claim", None)):
            raise ValueError("A verifier claim releaser is required")
        if not callable(getattr(store, "finalize_success", None)):
            raise ValueError("A trusted task finalizer is required")
        if not callable(getattr(store, "record_inconclusive", None)):
            raise ValueError("A durable inconclusive-outcome recorder is required")
        if collector is None or not callable(getattr(collector, "collect", None)):
            raise ValueError("An independent evidence collector is required")
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= 20:
            raise ValueError("batch_size must be between 1 and 20")
        self._store = store
        self._collector = collector
        self._batch_size = batch_size

    def run_once(self) -> VerifierBatchResult:
        """Atomically claim and process a bounded batch; abandoned claims expire."""
        pending = self._store.claim_awaiting_verification(limit=self._batch_size, lease_seconds=120)
        finalized = 0
        inconclusive = 0
        lost_race = 0
        for task, report in pending:
            decision = verify_github_repository_task(task, report, collector=self._collector)
            if decision.status is not VerificationStatus.VERIFIED_SUCCESS:
                # Persist the result through the task/tenant/claim-token fence.
                # The database applies bounded retries and moves exhausted
                # tasks to HUMAN_REVIEW_REQUIRED; no inconclusive result can
                # reach the success finalizer.
                self._store.record_inconclusive(
                    task=task,
                    reason_code=decision.reason,
                )
                inconclusive += 1
                continue
            if self._store.finalize_success(task=task, decision=decision):
                finalized += 1
            else:
                # A lost finalization race is safe to release: the database
                # routine already proved this token no longer owns the task.
                lost_race += 1
                self._store.release_claim(task=task)
        return VerifierBatchResult(
            scanned=len(pending), finalized=finalized, inconclusive=inconclusive,
            lost_finalization_race=lost_race,
        )


def build_github_repository_verifier(
    *,
    verifier_dsn: str,
    credential_provider: TenantGitHubInstallationProvider,
    collector_id: str,
    batch_size: int = 10,
) -> AgentTaskVerifier:
    """Compose a verifier using a dedicated DB identity and tenant credential provider."""
    if not isinstance(verifier_dsn, str) or not verifier_dsn.strip():
        raise ValueError("A dedicated verifier PostgreSQL DSN is required")
    collector = TenantGitHubEvidenceCollector(
        collector_id=collector_id,
        credential_provider=credential_provider,
    )
    store = PostgresAgentTaskVerifierStore(verifier_dsn)
    return AgentTaskVerifier(
        store=store,
        collector=collector,
        batch_size=batch_size,
    )


__all__ = [
    "AgentTaskVerifier",
    "VerifierBatchResult",
    "build_github_repository_verifier",
]
