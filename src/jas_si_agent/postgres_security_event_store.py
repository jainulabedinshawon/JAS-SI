"""PostgreSQL-backed security event persistence and verification."""

from __future__ import annotations

import hmac
from typing import Any, Mapping

from jas_si_agent.security_event_store import (
    MAX_EVENT_BYTES,
    SecurityEventStoreError,
    _canonical_json,
    _event_hash,
)


GENESIS_HASH = "0" * 64


def _valid_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


class PostgresSecurityEventStore:
    """Persist and verify hash-chained audit events in PostgreSQL."""

    def __init__(self, dsn: str) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("PostgreSQL DSN is required")

        self.dsn = dsn.strip()

    @staticmethod
    def append_in_transaction(connection: Any, event: Mapping[str, Any]) -> None:
        """Append an event using the caller's transaction and connection.

        The caller owns commit/rollback. This method never opens or commits a
        separate transaction, so callers can atomically couple audit writes
        with their business-data changes.
        """
        if not isinstance(event, Mapping):
            raise SecurityEventStoreError("Event must be a mapping")

        event_data = dict(event)
        if "_integrity" in event_data:
            raise SecurityEventStoreError("Reserved integrity field")

        try:
            event_bytes = _canonical_json(event_data)
        except (TypeError, ValueError, RecursionError) as exc:
            raise SecurityEventStoreError(
                "Event is not valid JSON data"
            ) from exc
        if len(event_bytes) + 1024 > MAX_EVENT_BYTES:
            raise SecurityEventStoreError("Security event exceeds 64 KiB")

        try:
            from psycopg.types.json import Jsonb

            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO jas_si_audit_chain_state (singleton, last_hash)
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
                if not _valid_hash(previous_hash):
                    raise SecurityEventStoreError(
                        "Invalid database chain checkpoint"
                    )

                cursor.execute("SELECT %s::jsonb", (Jsonb(event_data),))
                normalized_row = cursor.fetchone()
                if (
                    normalized_row is None
                    or not isinstance(normalized_row[0], dict)
                ):
                    raise SecurityEventStoreError(
                        "Unable to normalize audit event"
                    )

                normalized_event = normalized_row[0]
                new_hash = _event_hash(normalized_event, previous_hash)
                cursor.execute(
                    """
                    INSERT INTO jas_si_audit_events
                        (event_payload, previous_hash, event_hash)
                    VALUES (%s, %s, %s)
                    """,
                    (Jsonb(normalized_event), previous_hash, new_hash),
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
                "Unable to append PostgreSQL security event in transaction"
            ) from exc

    def append(self, event: Mapping[str, Any]) -> None:
        """Atomically append one hash-chained security event."""
        try:
            import psycopg

            with psycopg.connect(self.dsn) as connection:
                self.append_in_transaction(connection, event)
        except SecurityEventStoreError:
            raise
        except Exception as exc:
            raise SecurityEventStoreError(
                "Unable to persist PostgreSQL security event"
            ) from exc

    @staticmethod
    def verify_integrity_in_transaction(connection: Any) -> dict[str, Any]:
        """Verify the full chain using the caller's current transaction.

        Callers that need to append after verification must first lock the
        singleton checkpoint row FOR UPDATE. All appenders use the same lock.
        """
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT event_payload, previous_hash, event_hash
                    FROM jas_si_audit_events
                    ORDER BY event_id ASC
                    """
                )
                rows = cursor.fetchall()
                cursor.execute(
                    """
                    SELECT last_hash
                    FROM jas_si_audit_chain_state
                    WHERE singleton = TRUE
                    """
                )
                checkpoint_row = cursor.fetchone()

            previous_hash = GENESIS_HASH
            verified_count = 0
            for event_number, row in enumerate(rows, start=1):
                payload, recorded_previous, recorded_hash = row
                if not isinstance(payload, dict):
                    raise SecurityEventStoreError(
                        f"Invalid event payload at position {event_number}"
                    )
                if not _valid_hash(recorded_previous):
                    raise SecurityEventStoreError(
                        f"Invalid previous hash at position {event_number}"
                    )
                if not _valid_hash(recorded_hash):
                    raise SecurityEventStoreError(
                        f"Invalid event hash at position {event_number}"
                    )
                if not hmac.compare_digest(recorded_previous, previous_hash):
                    raise SecurityEventStoreError(
                        f"Hash-chain link mismatch at position {event_number}"
                    )
                try:
                    expected_hash = _event_hash(payload, previous_hash)
                except (TypeError, ValueError, RecursionError) as exc:
                    raise SecurityEventStoreError(
                        f"Invalid event data at position {event_number}"
                    ) from exc
                if not hmac.compare_digest(recorded_hash, expected_hash):
                    raise SecurityEventStoreError(
                        f"Event hash mismatch at position {event_number}"
                    )
                previous_hash = recorded_hash
                verified_count += 1

            if checkpoint_row is None:
                if rows:
                    raise SecurityEventStoreError("Audit checkpoint is missing")
                checkpoint_hash = GENESIS_HASH
            else:
                checkpoint_hash = checkpoint_row[0]
            if not _valid_hash(checkpoint_hash):
                raise SecurityEventStoreError("Invalid database chain checkpoint")
            if not hmac.compare_digest(checkpoint_hash, previous_hash):
                raise SecurityEventStoreError(
                    "Database checkpoint does not match verified chain"
                )
            return {
                "valid": True,
                "verified_event_count": verified_count,
                "last_hash": previous_hash,
            }
        except SecurityEventStoreError:
            raise
        except Exception as exc:
            raise SecurityEventStoreError(
                "Unable to verify PostgreSQL audit chain in transaction"
            ) from exc

    def verify_integrity(self) -> dict[str, Any]:
        """Verify every event and checkpoint in a repeatable-read snapshot."""
        try:
            import psycopg
            with psycopg.connect(self.dsn) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
                    )
                return self.verify_integrity_in_transaction(connection)
        except SecurityEventStoreError:
            raise
        except Exception as exc:
            raise SecurityEventStoreError(
                "Unable to verify PostgreSQL audit chain"
            ) from exc
