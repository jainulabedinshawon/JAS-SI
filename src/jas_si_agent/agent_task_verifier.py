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
    def list_awaiting_verification(self, *, limit: int = 10):
        ...

    def finalize_success(self, *, task, decision) -> bool:
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
        if store is None or not callable(getattr(store, "list_awaiting_verification", None)):
            raise ValueError("A trusted persisted-task verifier store is required")
        if not callable(getattr(store, "finalize_success", None)):
            raise ValueError("A trusted task finalizer is required")
        if collector is None or not callable(getattr(collector, "collect", None)):
            raise ValueError("An independent evidence collector is required")
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= 20:
            raise ValueError("batch_size must be between 1 and 20")
        self._store = store
        self._collector = collector
        self._batch_size = batch_size

    def run_once(self) -> VerifierBatchResult:
        """Process at most batch_size records; inconclusive tasks remain pending."""
        pending = self._store.list_awaiting_verification(limit=self._batch_size)
        finalized = 0
        inconclusive = 0
        lost_race = 0
        for task, report in pending:
            decision = verify_github_repository_task(
                task,
                report,
                collector=self._collector,
            )
            if decision.status is not VerificationStatus.VERIFIED_SUCCESS:
                inconclusive += 1
                continue
            if self._store.finalize_success(task=task, decision=decision):
                finalized += 1
            else:
                # Another verifier may have finalized or the task may have
                # changed state while independent evidence was being collected.
                lost_race += 1
        return VerifierBatchResult(
            scanned=len(pending),
            finalized=finalized,
            inconclusive=inconclusive,
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
