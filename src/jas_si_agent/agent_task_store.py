"""Tenant-scoped durable task persistence for the JAS-SI Agent Core.

This store persists accepted work and exposes retrieval/cancellation. It does
not claim to execute tasks, run tools, or verify outcomes.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping


class AgentTaskStoreError(RuntimeError):
    """Durable task persistence or authorization failed."""


class AgentTaskIdempotencyConflict(AgentTaskStoreError):
    """An idempotency key was reused for a different request."""


@dataclass(frozen=True)
class AgentTask:
    task_id: uuid.UUID
    task_type: str
    status: str
    input_payload: dict[str, Any]
    result_payload: dict[str, Any] | None
    error_code: str | None
    attempt_count: int
    max_attempts: int
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None


@dataclass(frozen=True)
class AgentTaskSubmission:
    task: AgentTask
    created: bool


class PostgresAgentTaskStore:
    """Use API-key-derived tenant identity inside database-owned routines."""

    def __init__(self, dsn: str) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("PostgreSQL DSN is required")
        self._dsn = dsn.strip()

    def verify_schema(self) -> bool:
        """Fail closed unless the runtime can call the tenant-scoped task routines."""
        import psycopg

        with psycopg.connect(self._dsn) as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT
                     pg_catalog.to_regclass('public.jas_si_agent_tasks') IS NOT NULL,
                     pg_catalog.to_regprocedure('public.jas_si_agent_task_create(uuid,uuid,bytea,text,bytea,text,jsonb,integer)') IS NOT NULL,
                     pg_catalog.to_regprocedure('public.jas_si_agent_task_get(uuid,bytea,uuid)') IS NOT NULL,
                     pg_catalog.to_regprocedure('public.jas_si_agent_task_cancel(uuid,bytea,uuid)') IS NOT NULL,
                     pg_catalog.has_function_privilege(
                       current_user,
                       'public.jas_si_agent_task_create(uuid,uuid,bytea,text,bytea,text,jsonb,integer)',
                       'EXECUTE'
                     ),
                     pg_catalog.has_function_privilege(
                       current_user,
                       'public.jas_si_agent_task_get(uuid,bytea,uuid)',
                       'EXECUTE'
                     ),
                     pg_catalog.has_function_privilege(
                       current_user,
                       'public.jas_si_agent_task_cancel(uuid,bytea,uuid)',
                       'EXECUTE'
                     ),
                     NOT pg_catalog.has_table_privilege(
                       current_user,'public.jas_si_agent_tasks','SELECT'
                     ),
                     NOT pg_catalog.has_table_privilege(
                       current_user,'public.jas_si_agent_tasks','INSERT'
                     ),
                     NOT pg_catalog.has_table_privilege(
                       current_user,'public.jas_si_agent_tasks','UPDATE'
                     ),
                     NOT pg_catalog.has_table_privilege(
                       current_user,'public.jas_si_agent_tasks','DELETE'
                     ),
                     NOT pg_catalog.has_table_privilege(
                       current_user,'public.jas_si_agent_tasks','TRUNCATE'
                     ),
                     NOT pg_catalog.has_any_column_privilege(
                       current_user,'public.jas_si_agent_tasks','SELECT'
                     ),
                     NOT pg_catalog.has_any_column_privilege(
                       current_user,'public.jas_si_agent_tasks','INSERT'
                     ),
                     NOT pg_catalog.has_any_column_privilege(
                       current_user,'public.jas_si_agent_tasks','UPDATE'
                     )
                """
            )
            row = cursor.fetchone()
        return bool(row and all(value is True for value in row))

    @staticmethod
    def _validate_request(
        *,
        idempotency_key: str,
        task_type: str,
        input_payload: Mapping[str, Any],
        max_attempts: int,
    ) -> tuple[dict[str, Any], bytes]:
        if (
            not isinstance(idempotency_key, str)
            or re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", idempotency_key) is None
        ):
            raise ValueError("Invalid idempotency key")
        if (
            not isinstance(task_type, str)
            or not task_type.strip()
            or len(task_type.strip()) > 64
        ):
            raise ValueError("Invalid task type")
        if not isinstance(input_payload, Mapping):
            raise ValueError("Task input must be a mapping")
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or not 1 <= max_attempts <= 10:
            raise ValueError("max_attempts must be between 1 and 10")

        try:
            normalized = json.loads(
                json.dumps(dict(input_payload), ensure_ascii=False, allow_nan=False)
            )
            encoded = json.dumps(
                normalized, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("Task input must be finite JSON data") from exc
        if not isinstance(normalized, dict) or len(encoded) > 65536:
            raise ValueError("Task input must be a JSON object no larger than 64 KiB")
        return normalized, hashlib.sha256(encoded).digest()

    @staticmethod
    def _to_task(row: tuple[Any, ...]) -> AgentTask:
        return AgentTask(
            task_id=row[0], task_type=row[1], status=row[2],
            input_payload=row[3], result_payload=row[4], error_code=row[5],
            attempt_count=row[6], max_attempts=row[7], created_at=row[8],
            updated_at=row[9], completed_at=row[10],
        )

    def create(
        self,
        *,
        api_key_id: uuid.UUID,
        candidate_digest: bytes,
        idempotency_key: str,
        task_type: str,
        input_payload: Mapping[str, Any],
        max_attempts: int = 3,
    ) -> AgentTaskSubmission:
        if not isinstance(api_key_id, uuid.UUID):
            raise ValueError("api_key_id must be a UUID")
        if not isinstance(candidate_digest, bytes) or len(candidate_digest) != 32:
            raise ValueError("candidate_digest must be 32 bytes")
        payload, _ = self._validate_request(
            idempotency_key=idempotency_key, task_type=task_type,
            input_payload=input_payload, max_attempts=max_attempts,
        )
        request_material = json.dumps(
            {"task_type": task_type.strip(), "input_payload": payload,
             "max_attempts": max_attempts},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        request_hash = hashlib.sha256(request_material).digest()
        task_id = uuid.uuid4()
        try:
            import psycopg
            from psycopg.types.json import Jsonb

            with psycopg.connect(self._dsn) as connection, connection.cursor() as cursor:
                cursor.execute(
                    """SELECT task_id,status,created,task_type,input_payload,
                              result_payload,error_code,attempt_count,max_attempts,
                              created_at,updated_at,completed_at
                       FROM public.jas_si_agent_task_create(
                         %s,%s,%s,%s,%s,%s,%s,%s)""",
                    (task_id, api_key_id, candidate_digest, idempotency_key,
                     request_hash, task_type.strip(), Jsonb(payload), max_attempts),
                )
                row = cursor.fetchone()
                if row is None:
                    raise AgentTaskStoreError("Task creation returned no durable record")
                task = AgentTask(
                    task_id=row[0], status=row[1], task_type=row[3],
                    input_payload=row[4], result_payload=row[5], error_code=row[6],
                    attempt_count=row[7], max_attempts=row[8], created_at=row[9],
                    updated_at=row[10], completed_at=row[11],
                )
            return AgentTaskSubmission(task, bool(row[2]))
        except AgentTaskStoreError:
            raise
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == "22023":
                raise AgentTaskIdempotencyConflict(
                    "Idempotency key conflicts with a different request"
                ) from exc
            raise AgentTaskStoreError("Unable to persist agent task") from exc

    def get(
        self, *, api_key_id: uuid.UUID, candidate_digest: bytes,
        task_id: uuid.UUID,
    ) -> AgentTask | None:
        if not isinstance(api_key_id, uuid.UUID) or not isinstance(task_id, uuid.UUID):
            raise ValueError("API key and task identifiers must be UUIDs")
        if not isinstance(candidate_digest, bytes) or len(candidate_digest) != 32:
            raise ValueError("candidate_digest must be 32 bytes")
        try:
            import psycopg
            with psycopg.connect(self._dsn) as connection, connection.cursor() as cursor:
                cursor.execute(
                    """SELECT task_id,task_type,status,input_payload,result_payload,
                              error_code,attempt_count,max_attempts,created_at,
                              updated_at,completed_at
                       FROM public.jas_si_agent_task_get(%s,%s,%s)""",
                    (api_key_id, candidate_digest, task_id),
                )
                row = cursor.fetchone()
            return self._to_task(row) if row else None
        except Exception as exc:
            raise AgentTaskStoreError("Unable to retrieve agent task") from exc

    def cancel(
        self, *, api_key_id: uuid.UUID, candidate_digest: bytes,
        task_id: uuid.UUID,
    ) -> bool:
        if not isinstance(api_key_id, uuid.UUID) or not isinstance(task_id, uuid.UUID):
            raise ValueError("API key and task identifiers must be UUIDs")
        if not isinstance(candidate_digest, bytes) or len(candidate_digest) != 32:
            raise ValueError("candidate_digest must be 32 bytes")
        try:
            import psycopg
            with psycopg.connect(self._dsn) as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT public.jas_si_agent_task_cancel(%s,%s,%s)",
                    (api_key_id, candidate_digest, task_id),
                )
                return bool(cursor.fetchone()[0])
        except Exception as exc:
            raise AgentTaskStoreError("Unable to cancel agent task") from exc
