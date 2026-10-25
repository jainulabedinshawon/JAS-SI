
"""Validated, thread-safe wrapper for the existing JAS-SI audit store.

This writer persists existing AuditRecord objects. It does not execute
actions, generate authorization decisions, or replace the audit hash chain.
The underlying store still assumes a single writer across processes.
"""

from __future__ import annotations

import threading
from typing import Optional

from jas_si_agent.audit_log import AuditRecord
from jas_si_agent.audit_store import (
    AuditStoreError,
    JsonlAuditStore,
)


class AuditWriter:
    """Serialize writes through one writer instance."""

    def __init__(self, store: JsonlAuditStore) -> None:
        if not isinstance(store, JsonlAuditStore):
            raise TypeError("store must be a JsonlAuditStore")

        self._store = store
        self._lock = threading.RLock()

    @property
    def store(self) -> JsonlAuditStore:
        """Return the configured underlying store."""
        return self._store

    def write(self, record: AuditRecord) -> None:
        """Validate and append one existing audit record.

        The underlying store checks record fields, sequence, hash, and chain.
        Exceptions are allowed to propagate so callers cannot mistake a
        failed write for a successful audit operation.
        """
        if not isinstance(record, AuditRecord):
            raise AuditStoreError("record must be an AuditRecord")

        with self._lock:
            self._store.append(record)

    def append(self, record: AuditRecord) -> None:
        """Alias for write(), for callers that prefer append terminology."""
        self.write(record)

    def load_records(self) -> tuple[AuditRecord, ...]:
        """Return the store's validated records."""
        with self._lock:
            return self._store.load_records()


__all__ = ["AuditWriter", "AuditStoreError"]
