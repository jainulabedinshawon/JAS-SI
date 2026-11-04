"""PostgreSQL-backed security event persistence."""

from __future__ import annotations

from typing import Any, Mapping

from jas_si_agent.security_event_store import (
    MAX_EVENT_BYTES,
    SecurityEventStoreError,
    _canonical_json,
    _event_hash,
)


GENESIS_HASH = "0" * 64


class PostgresSecurityEventStore:
    """Persist hash-chained audit events in PostgreSQL.

    The database migration must be applied before use.
    Each append uses a database transaction and row-level locking.
    """

    def __init__(self, dsn: str) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("PostgreSQL DSN is required")

        self.dsn = dsn.strip()

    def append(self, event: Mapping[str, Any]) -> None:
        """Atomically append one hash-chained security event."""

        if not isinstance(event, Mapping):
            raise SecurityEventStoreError(
                "Event must be a mapping"
            )

        event_data = dict(event)

        if "_integrity" in event_data:
            raise SecurityEventStoreError(
                "Reserved integrity field"
            )

        try:
            event_bytes = _canonical_json(event_data)
        except (TypeError, ValueError, RecursionError) as exc:
            raise SecurityEventStoreError(
                "Event is not valid JSON data"
            ) from exc

        if len(event_bytes) + 1024 > MAX_EVENT_BYTES:
            raise SecurityEventStoreError(
                "Security event exceeds 64 KiB"
            )

        try:
            import psycopg
            from psycopg.types.json import Jsonb

            with psycopg.connect(self.dsn) as connection:
                with connection.cursor() as cursor:

                    cursor.execute(
                        """
                        INSERT INTO jas_si_audit_chain_state (
                            singleton,
                            last_hash
                        )
                        VALUES (TRUE, %s)
                        ON CONFLICT (singleton) DO NOTHING
                        """,
                        (GENESIS_HASH,),
                    )

                    cursor.execute(
                        """
                        SELECT last_hash
                        FROM jas_si_audit_chain_state
                        WHERE singleton = TRUE
                        FOR UPDATE
                        """
                    )

                    row = cursor.fetchone()

                    if row is None:
                        raise SecurityEventStoreError(
                            "Audit chain state is unavailable"
                        )

                    previous_hash = row[0]

                    if (
                        not isinstance(previous_hash, str)
                        or len(previous_hash) != 64
                        or any(
                            char not in "0123456789abcdef"
                            for char in previous_hash
                        )
                    ):
                        raise SecurityEventStoreError(
                            "Invalid database chain checkpoint"
                        )

                    new_hash = _event_hash(
                        event_data,
                        previous_hash,
                    )

                    cursor.execute(
                        """
                        INSERT INTO jas_si_audit_events (
                            event_payload,
                            previous_hash,
                            event_hash
                        )
                        VALUES (%s, %s, %s)
                        """,
                        (
                            Jsonb(event_data),
                            previous_hash,
                            new_hash,
                        ),
                    )

                    cursor.execute(
                        """
                        UPDATE jas_si_audit_chain_state
                        SET last_hash = %s
                        WHERE singleton = TRUE
                        """,
                        (new_hash,),
                    )

        except SecurityEventStoreError:
            raise
        except Exception as exc:
            raise SecurityEventStoreError(
                "Unable to persist PostgreSQL security event"
            ) from exc
