"""Least-privilege persistence adapter for trusted verifier finalization.

The DSN must authenticate as a dedicated login role that is a member of the
non-login jas_si_agent_verifier capability role. It is never the public API
or worker DSN. Only independently verified GitHub repository-read successes
can be finalized through this adapter.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from jas_si_agent.github_task_verifier import (
    PersistedTask,
    TaskVerificationDecision,
    WorkerTaskReport,
)
from jas_si_agent.verification import VerificationStatus


class AgentTaskVerifierStoreError(RuntimeError):
    """Trusted verifier persistence or finalization failed."""


class PostgresAgentTaskVerifierStore:
    """Persist evidence and atomically finalize a task through a DB routine."""

    def __init__(self, dsn: str) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("Dedicated verifier PostgreSQL DSN is required")
        self._dsn = dsn.strip()

    def list_awaiting_verification(
        self, *, limit: int = 10
    ) -> list[tuple[PersistedTask, WorkerTaskReport]]:
        """Load a bounded batch of persisted task reports for independent verification."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
            raise ValueError("verification batch limit must be between 1 and 20")
        try:
            import psycopg

            with psycopg.connect(self._dsn) as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT task_id,tenant_id,task_type,input_payload,result_payload,reported_at "
                    "FROM public.jas_si_agent_task_verification_list(%s)",
                    (limit,),
                )
                rows = cursor.fetchall()
            items: list[tuple[PersistedTask, WorkerTaskReport]] = []
            for row in rows:
                task_id, tenant_id, task_type, input_payload, result_payload, _reported_at = row
                if (
                    not isinstance(task_id, uuid.UUID)
                    or not isinstance(tenant_id, uuid.UUID)
                    or task_type != "github.read_repository"
                    or not isinstance(input_payload, dict)
                    or not isinstance(result_payload, dict)
                ):
                    raise AgentTaskVerifierStoreError(
                        "Verifier queue returned an invalid persisted task"
                    )
                task = PersistedTask(
                    task_id=task_id,
                    tenant_id=tenant_id,
                    task_type=task_type,
                    input_payload=input_payload,
                )
                # Only tasks in awaiting_verification are returned by the
                # database-owned routine, so a persisted result means the
                # worker completed its handler. Its evidence claims remain
                # untrusted and are cross-checked by the independent collector.
                report = WorkerTaskReport(
                    task_id=task_id,
                    claimed_success=True,
                    result_payload=result_payload,
                )
                items.append((task, report))
            return items
        except (ImportError, ValueError, AgentTaskVerifierStoreError):
            raise
        except Exception as exc:
            raise AgentTaskVerifierStoreError(
                "Unable to load pending agent task verification records"
            ) from exc

    @staticmethod
    def _evidence_payload(
        task: PersistedTask,
        decision: TaskVerificationDecision,
    ) -> tuple[dict[str, Any], bytes, datetime]:
        if not isinstance(task, PersistedTask):
            raise ValueError("Persisted task is required")
        if task.task_type != "github.read_repository" or not isinstance(task.input_payload, dict):
            raise ValueError("Only a persisted GitHub repository-read task can be finalized")
        if not isinstance(decision, TaskVerificationDecision):
            raise ValueError("Trusted verification decision is required")
        if decision.task_id != task.task_id:
            raise ValueError("Verification decision task binding mismatch")
        if decision.status is not VerificationStatus.VERIFIED_SUCCESS:
            raise ValueError("Only independently verified success may be finalized")
        evidence = decision.evidence
        if evidence is None:
            raise ValueError("Independent evidence is required")
        if (
            not isinstance(evidence.collector_id, str)
            or not evidence.collector_id.strip()
            or len(evidence.collector_id) > 128
            or not isinstance(evidence.collected_at, datetime)
            or evidence.collected_at.tzinfo is None
            or evidence.collected_at.utcoffset() is None
            or evidence.collected_at > datetime.now(timezone.utc)
            or not isinstance(evidence.repository, str)
            or evidence.repository.casefold()
            != str(task.input_payload.get("repository", "")).casefold()
            or not isinstance(evidence.commit_sha, str)
            or evidence.commit_sha != task.input_payload.get("commit_sha")
            or not isinstance(evidence.tree_sha, str)
            or len(evidence.tree_sha) != 40
            or any(char not in "0123456789abcdef" for char in evidence.tree_sha)
            or not isinstance(evidence.content_digest, str)
            or len(evidence.content_digest) != 64
            or any(char not in "0123456789abcdef" for char in evidence.content_digest)
            or not isinstance(evidence.files, tuple)
        ):
            raise ValueError("Independent evidence is not bound to the persisted task")
        requested_paths = task.input_payload.get("paths")
        if (
            not isinstance(requested_paths, list)
            or not requested_paths
            or len(evidence.files) != len(requested_paths)
            or len({item.get("path") for item in evidence.files if isinstance(item, dict)})
            != len(evidence.files)
        ):
            raise ValueError("Independent evidence file set is invalid")
        observed_paths = set()
        for item in evidence.files:
            if not isinstance(item, dict):
                raise ValueError("Independent evidence file record is invalid")
            path = item.get("path")
            blob_sha = item.get("blob_sha")
            sha256 = item.get("sha256")
            size_bytes = item.get("size_bytes")
            if (
                not isinstance(path, str)
                or not path
                or path not in requested_paths
                or item.get("integrity") != "VERIFIED"
                or not isinstance(blob_sha, str)
                or len(blob_sha) != 40
                or any(char not in "0123456789abcdef" for char in blob_sha)
                or not isinstance(sha256, str)
                or len(sha256) != 64
                or any(char not in "0123456789abcdef" for char in sha256)
                or isinstance(size_bytes, bool)
                or not isinstance(size_bytes, int)
                or size_bytes < 0
            ):
                raise ValueError("Independent evidence file integrity is invalid")
            observed_paths.add(path)
        if observed_paths != set(requested_paths):
            raise ValueError("Independent evidence does not cover the requested files")
        try:
            digest = bytes.fromhex(evidence.content_digest)
        except ValueError as exc:
            raise ValueError("Invalid independent evidence digest") from exc
        if len(digest) != 32:
            raise ValueError("Invalid independent evidence digest")

        files = [dict(item) for item in evidence.files]
        canonical = "|".join(
            [
                evidence.repository,
                evidence.commit_sha,
                evidence.tree_sha,
                *[
                    f"{item.get('path', '')}:{item.get('blob_sha', '')}:{item.get('sha256', '')}"
                    for item in evidence.files
                ],
            ]
        ).encode("utf-8")
        if hashlib.sha256(canonical).digest() != digest:
            raise ValueError("Independent evidence digest does not match its contents")

        payload = {
            "task_id": str(task.task_id),
            "tenant_id": str(task.tenant_id),
            "collector_id": evidence.collector_id,
            "verification_status": decision.status.value,
            "repository": evidence.repository,
            "commit_sha": evidence.commit_sha,
            "tree_sha": evidence.tree_sha,
            "files": files,
            "evidence_digest": evidence.content_digest,
            "collected_at": evidence.collected_at.astimezone(timezone.utc).isoformat(),
            "verification_reason": decision.reason,
        }
        # Ensure the payload is finite JSON and remains below the database bound.
        try:
            encoded = json.dumps(
                payload, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("Independent evidence must be finite JSON data") from exc
        if len(encoded) > 65536:
            raise ValueError("Independent evidence exceeds the 64 KiB persistence limit")
        return payload, digest, evidence.collected_at.astimezone(timezone.utc)

    def finalize_success(
        self,
        *,
        task: PersistedTask,
        decision: TaskVerificationDecision,
    ) -> bool:
        """Atomically persist the evidence and finalize only its bound task."""
        if not isinstance(task, PersistedTask):
            raise ValueError("Persisted task is required")
        if not isinstance(task.task_id, uuid.UUID) or not isinstance(task.tenant_id, uuid.UUID):
            raise ValueError("Persisted task and tenant IDs must be UUIDs")
        payload, digest, collected_at = self._evidence_payload(task, decision)
        evidence_id = uuid.uuid4()
        try:
            import psycopg
            from psycopg.types.json import Jsonb

            with psycopg.connect(self._dsn) as connection, connection.cursor() as cursor:
                cursor.execute(
                    """SELECT public.jas_si_agent_task_finalize_success(
                         %s,%s,%s,%s,%s,%s,%s
                       )""",
                    (
                        evidence_id,
                        task.task_id,
                        task.tenant_id,
                        payload["collector_id"],
                        digest,
                        Jsonb(payload),
                        collected_at,
                    ),
                )
                row = cursor.fetchone()
            if row is None:
                raise AgentTaskVerifierStoreError(
                    "Verifier finalization returned no database result"
                )
            return bool(row[0])
        except (ImportError, ValueError, AgentTaskVerifierStoreError):
            raise
        except Exception as exc:
            raise AgentTaskVerifierStoreError(
                "Unable to persist independent evidence or finalize task"
            ) from exc


__all__ = [
    "AgentTaskVerifierStoreError",
    "PostgresAgentTaskVerifierStore",
]
