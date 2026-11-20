"""Evidence-only recollection for customer-requested independent re-verification.

This process only reads the immutable original task scope. It never invokes the
Worker, changes task input, or replays an action.
"""
from __future__ import annotations

from dataclasses import dataclass
import uuid
from typing import Any

from jas_si_agent.agent_task_verifier_store import (
    AgentTaskVerifierStoreError,
    PostgresAgentTaskVerifierStore,
)
from jas_si_agent.github_task_verifier import (
    GitHubEvidenceCollector,
    PersistedTask,
    TaskVerificationDecision,
    TenantGitHubEvidenceCollector,
    WorkerTaskReport,
    verify_github_repository_task,
)
from jas_si_agent.github_installations import TenantGitHubInstallationProvider
from jas_si_agent.verification import VerificationStatus


@dataclass(frozen=True)
class EvidenceRecollectionBatchResult:
    scanned: int
    finalized: int
    inconclusive: int
    lost_claim: int


class PostgresAgentEvidenceRequestStore:
    """Dedicated-verifier adapter for evidence-only request claim and finalization."""

    def __init__(self, dsn: str) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("Dedicated verifier PostgreSQL DSN is required")
        self._dsn = dsn.strip()

    def claim_pending(self, *, limit: int = 10, lease_seconds: int = 120):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
            raise ValueError("evidence request batch limit must be between 1 and 20")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 5 <= lease_seconds <= 300:
            raise ValueError("evidence request lease must be between 5 and 300 seconds")
        try:
            import psycopg
            with psycopg.connect(self._dsn) as connection, connection.cursor() as cursor:
                cursor.execute(
                    """SELECT request_id,task_id,tenant_id,task_type,input_payload,
                              result_payload,claim_token
                         FROM public.jas_si_agent_evidence_request_claim(%s,%s)""",
                    (limit, lease_seconds),
                )
                rows = cursor.fetchall()
            claimed = []
            for row in rows:
                request_id, task_id, tenant_id, task_type, input_payload, result_payload, token = row
                if (
                    not all(isinstance(value, uuid.UUID) for value in (request_id, task_id, tenant_id, token))
                    or task_type != "github.read_repository"
                    or not isinstance(input_payload, dict)
                    or not isinstance(result_payload, dict)
                ):
                    raise AgentTaskVerifierStoreError("Evidence request claim returned invalid persisted scope")
                task = PersistedTask(
                    task_id=task_id, tenant_id=tenant_id, task_type=task_type,
                    input_payload=input_payload, verifier_claim_token=token,
                )
                report = WorkerTaskReport(
                    task_id=task_id, claimed_success=True, result_payload=result_payload,
                )
                claimed.append((request_id, task, report))
            return claimed
        except (ImportError, ValueError, AgentTaskVerifierStoreError):
            raise
        except Exception as exc:
            raise AgentTaskVerifierStoreError("Unable to claim evidence recollection requests") from exc

    def record_inconclusive(self, *, request_id: uuid.UUID, task: PersistedTask, reason_code: str):
        import re
        if (
            not isinstance(request_id, uuid.UUID)
            or not isinstance(task, PersistedTask)
            or not isinstance(task.verifier_claim_token, uuid.UUID)
            or not isinstance(reason_code, str)
            or re.fullmatch(r"[A-Z0-9_]{1,64}", reason_code) is None
        ):
            raise ValueError("A valid claimed evidence request and reason code are required")
        try:
            import psycopg
            with psycopg.connect(self._dsn) as connection, connection.cursor() as cursor:
                cursor.execute(
                    """SELECT public.jas_si_agent_evidence_request_record_inconclusive(
                         %s,%s,%s,%s,%s)""",
                    (request_id, task.task_id, task.tenant_id, task.verifier_claim_token, reason_code),
                )
                row = cursor.fetchone()
            return row[0] if row else None
        except (ImportError, ValueError):
            raise
        except Exception as exc:
            raise AgentTaskVerifierStoreError("Unable to persist evidence recollection outcome") from exc

    def finalize_success(
        self, *, request_id: uuid.UUID, task: PersistedTask,
        decision: TaskVerificationDecision,
    ) -> bool:
        if not isinstance(request_id, uuid.UUID) or not isinstance(task.verifier_claim_token, uuid.UUID):
            raise ValueError("A claimed evidence request is required")
        # Reuse the exact payload validator used by the ordinary independent verifier.
        payload, digest, collected_at = PostgresAgentTaskVerifierStore._evidence_payload(task, decision)
        try:
            import psycopg
            from psycopg.types.json import Jsonb
            with psycopg.connect(self._dsn) as connection, connection.cursor() as cursor:
                cursor.execute(
                    """SELECT public.jas_si_agent_evidence_request_finalize_success(
                         %s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        request_id, task.task_id, task.tenant_id, task.verifier_claim_token,
                        uuid.uuid4(), payload["collector_id"], digest, Jsonb(payload), collected_at,
                    ),
                )
                row = cursor.fetchone()
            return bool(row and row[0])
        except (ImportError, ValueError):
            raise
        except Exception as exc:
            raise AgentTaskVerifierStoreError("Unable to finalize evidence-only recollection") from exc


class AgentTaskEvidenceRecollector:
    """Collect fresh evidence for review requests without executing Worker actions."""

    def __init__(self, *, store: PostgresAgentEvidenceRequestStore,
                 collector: GitHubEvidenceCollector, batch_size: int = 10) -> None:
        if store is None or not callable(getattr(store, "claim_pending", None)):
            raise ValueError("A persisted evidence-request store is required")
        if collector is None or not callable(getattr(collector, "collect", None)):
            raise ValueError("An independent GitHub evidence collector is required")
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= 20:
            raise ValueError("batch_size must be between 1 and 20")
        self._store, self._collector, self._batch_size = store, collector, batch_size

    def run_once(self) -> EvidenceRecollectionBatchResult:
        claimed = self._store.claim_pending(limit=self._batch_size, lease_seconds=120)
        finalized = inconclusive = lost = 0
        for request_id, task, report in claimed:
            decision = verify_github_repository_task(task, report, collector=self._collector)
            if decision.status is not VerificationStatus.VERIFIED_SUCCESS:
                outcome = self._store.record_inconclusive(
                    request_id=request_id, task=task, reason_code=decision.reason,
                )
                if outcome is None:
                    lost += 1
                else:
                    inconclusive += 1
                continue
            if self._store.finalize_success(
                request_id=request_id, task=task, decision=decision,
            ):
                finalized += 1
            else:
                lost += 1
        return EvidenceRecollectionBatchResult(
            scanned=len(claimed), finalized=finalized,
            inconclusive=inconclusive, lost_claim=lost,
        )


def build_github_evidence_recollector(
    *, verifier_dsn: str, credential_provider: TenantGitHubInstallationProvider,
    collector_id: str, batch_size: int = 10,
) -> AgentTaskEvidenceRecollector:
    if not isinstance(verifier_dsn, str) or not verifier_dsn.strip():
        raise ValueError("A dedicated verifier PostgreSQL DSN is required")
    collector = TenantGitHubEvidenceCollector(
        collector_id=collector_id, credential_provider=credential_provider,
    )
    return AgentTaskEvidenceRecollector(
        store=PostgresAgentEvidenceRequestStore(verifier_dsn),
        collector=collector, batch_size=batch_size,
    )


__all__ = [
    "AgentTaskEvidenceRecollector", "EvidenceRecollectionBatchResult",
    "PostgresAgentEvidenceRequestStore", "build_github_evidence_recollector",
]
