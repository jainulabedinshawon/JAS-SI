"""Least-privilege PostgreSQL adapter for JAS-SI task worker lifecycle routines.

This module only speaks to the database-owned worker routines. It does not
execute tools, call model providers, or decide task outcomes.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping


class AgentTaskWorkerStoreError(RuntimeError):
    """A worker lifecycle database operation could not be completed."""


@dataclass(frozen=True)
class AgentTaskLease:
    task_id: uuid.UUID
    tenant_id: uuid.UUID
    task_type: str
    input_payload: dict[str, Any]
    attempt_count: int
    max_attempts: int
    lease_fence: int
    lease_expires_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, uuid.UUID):
            raise ValueError("task_id must be a UUID")
        if not isinstance(self.tenant_id, uuid.UUID):
            raise ValueError("tenant_id must be a UUID")


class PostgresAgentTaskWorkerStore:
    """Call SECURITY DEFINER routines using a dedicated worker database identity.

    The DSN must authenticate as a login role that is a member of the
    non-login jas_si_agent_worker capability role. The public API runtime
    must never use this connection.
    """

    def __init__(self, dsn: str, worker_id: uuid.UUID) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("PostgreSQL DSN is required")
        if not isinstance(worker_id, uuid.UUID):
            raise ValueError("worker_id must be a UUID")
        self._dsn = dsn.strip()

    def _connect(self):
        """Open a fresh session and explicitly assume the non-login capability role."""
        import psycopg

        connection = psycopg.connect(self._dsn)
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET ROLE jas_si_agent_worker", None)
            return connection
        except Exception:
            connection.close()
            raise
        self._worker_id = worker_id

    @staticmethod
    def _validate_lease_seconds(value: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or not 15 <= value <= 300:
            raise ValueError("lease_seconds must be between 15 and 300")

    @staticmethod
    def _validate_task_fence(task_id: uuid.UUID, lease_fence: int) -> None:
        if not isinstance(task_id, uuid.UUID):
            raise ValueError("task_id must be a UUID")
        if isinstance(lease_fence, bool) or not isinstance(lease_fence, int) or lease_fence < 1:
            raise ValueError("lease_fence must be a positive integer")

    def claim(self, *, lease_seconds: int = 60) -> AgentTaskLease | None:
        """Atomically claim one eligible task or return None when the queue is empty."""
        self._validate_lease_seconds(lease_seconds)
        try:
            import psycopg

            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT task_id,tenant_id,task_type,input_payload,attempt_count,max_attempts,"
                    "lease_fence,lease_expires_at "
                    "FROM public.jas_si_agent_task_claim(%s,%s)",
                    (self._worker_id, lease_seconds),
                )
                row = cursor.fetchone()
            if row is None:
                return None
            return AgentTaskLease(
                task_id=row[0],
                tenant_id=row[1],
                task_type=row[2],
                input_payload=row[3],
                attempt_count=row[4],
                max_attempts=row[5],
                lease_fence=row[6],
                lease_expires_at=row[7],
            )
        except (ImportError, ValueError):
            raise
        except Exception as exc:
            raise AgentTaskWorkerStoreError("Unable to claim agent task") from exc

    def renew(
        self, *, task_id: uuid.UUID, lease_fence: int, lease_seconds: int = 60
    ) -> bool:
        """Renew only the current worker's unexpired lease and fencing token."""
        self._validate_task_fence(task_id, lease_fence)
        self._validate_lease_seconds(lease_seconds)
        try:
            import psycopg

            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT public.jas_si_agent_task_renew(%s,%s,%s,%s)",
                    (self._worker_id, task_id, lease_fence, lease_seconds),
                )
                row = cursor.fetchone()
            return bool(row and row[0])
        except (ImportError, ValueError):
            raise
        except Exception as exc:
            raise AgentTaskWorkerStoreError("Unable to renew agent task lease") from exc

    def acknowledge_cancel(
        self, *, task_id: uuid.UUID, lease_fence: int
    ) -> bool:
        """Acknowledge cancellation only while holding the current live lease."""
        self._validate_task_fence(task_id, lease_fence)
        try:
            import psycopg

            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT public.jas_si_agent_task_ack_cancel(%s,%s,%s)",
                    (self._worker_id, task_id, lease_fence),
                )
                row = cursor.fetchone()
            return bool(row and row[0])
        except (ImportError, ValueError):
            raise
        except Exception as exc:
            raise AgentTaskWorkerStoreError("Unable to acknowledge task cancellation") from exc

    @staticmethod
    def _validated_result(payload: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ValueError("result_payload must be a JSON object")
        try:
            normalized = json.loads(
                json.dumps(dict(payload), ensure_ascii=False, allow_nan=False)
            )
            encoded = json.dumps(
                normalized, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("result_payload must contain finite JSON data") from exc
        if not isinstance(normalized, dict) or len(encoded) > 65536:
            raise ValueError("result_payload must be an object no larger than 64 KiB")
        return normalized

    def report(
        self, *, task_id: uuid.UUID, lease_fence: int,
        result_payload: Mapping[str, Any],
    ) -> bool:
        """Submit a worker report; the database moves it to awaiting_verification."""
        self._validate_task_fence(task_id, lease_fence)
        normalized = self._validated_result(result_payload)
        try:
            import psycopg
            from psycopg.types.json import Jsonb

            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT public.jas_si_agent_task_report(%s,%s,%s,%s)",
                    (self._worker_id, task_id, lease_fence, Jsonb(normalized)),
                )
                row = cursor.fetchone()
            return bool(row and row[0])
        except (ImportError, ValueError):
            raise
        except Exception as exc:
            raise AgentTaskWorkerStoreError("Unable to report agent task result") from exc

    def fail(
        self, *, task_id: uuid.UUID, lease_fence: int, error_code: str,
        retry_delay_seconds: int = 0,
    ) -> str | None:
        """Report a bounded failure; the database decides retry or terminal state."""
        self._validate_task_fence(task_id, lease_fence)
        if not isinstance(error_code, str) or re.fullmatch(r"[A-Z0-9_]{1,64}", error_code) is None:
            raise ValueError("error_code must contain 1-64 uppercase letters, digits, or underscores")
        if (
            isinstance(retry_delay_seconds, bool)
            or not isinstance(retry_delay_seconds, int)
            or not 0 <= retry_delay_seconds <= 3600
        ):
            raise ValueError("retry_delay_seconds must be between 0 and 3600")
        try:
            import psycopg

            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT public.jas_si_agent_task_fail(%s,%s,%s,%s,%s)",
                    (self._worker_id, task_id, lease_fence, error_code, retry_delay_seconds),
                )
                row = cursor.fetchone()
            if row is None or row[0] is None:
                return None
            status = str(row[0])
            if status not in {"queued", "failed", "cancelled"}:
                raise AgentTaskWorkerStoreError("Database returned an invalid task failure state")
            return status
        except (ImportError, ValueError, AgentTaskWorkerStoreError):
            raise
        except Exception as exc:
            raise AgentTaskWorkerStoreError("Unable to report agent task failure") from exc
