
"""Durable JSONL storage for JAS-SI audit records.

This module persists and validates records. It does not execute actions.
Use one writer at a time; this is not a tamper-proof remote audit service.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from jas_si_agent.audit_log import (
    GENESIS_HASH,
    AuditRecord,
    _calculate_hash,
)


class AuditStoreError(ValueError):
    """Raised when stored audit data is invalid or inconsistent."""


class JsonlAuditStore:
    """Append-only JSONL store with hash-chain validation."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load_records(self) -> tuple[AuditRecord, ...]:
        """Load and validate all records; refuse malformed or tampered data."""
        if not self.path.exists():
            return ()

        if self.path.is_symlink():
            raise AuditStoreError("Symlink audit files are not allowed")

        records: list[AuditRecord] = []
        expected_previous_hash = GENESIS_HASH

        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        raise AuditStoreError(
                            f"Blank record at line {line_number}"
                        )

                    try:
                        data: Any = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise AuditStoreError(
                            f"Invalid JSON at line {line_number}"
                        ) from exc

                    if not isinstance(data, dict):
                        raise AuditStoreError(
                            f"Record at line {line_number} must be an object"
                        )

                    try:
                        record = AuditRecord(**data)
                    except (TypeError, ValueError) as exc:
                        raise AuditStoreError(
                            f"Invalid record fields at line {line_number}"
                        ) from exc

                    if record.sequence != len(records) + 1:
                        raise AuditStoreError(
                            f"Invalid sequence at line {line_number}"
                        )

                    if record.previous_hash != expected_previous_hash:
                        raise AuditStoreError(
                            f"Broken hash chain at line {line_number}"
                        )

                    if record.record_hash != _calculate_hash(record):
                        raise AuditStoreError(
                            f"Hash mismatch at line {line_number}"
                        )

                    records.append(record)
                    expected_previous_hash = record.record_hash

        except OSError as exc:
            raise AuditStoreError("Unable to read audit file") from exc

        return tuple(records)

    def append(self, record: AuditRecord) -> None:
        """Validate the existing chain and append one durable record."""
        if not isinstance(record, AuditRecord):
            raise TypeError("record must be an AuditRecord")

        existing = self.load_records()
        expected_previous_hash = (
            existing[-1].record_hash if existing else GENESIS_HASH
        )

        if record.sequence != len(existing) + 1:
            raise AuditStoreError("Unexpected record sequence")

        if record.previous_hash != expected_previous_hash:
            raise AuditStoreError("Record does not extend the current chain")

        if record.record_hash != _calculate_hash(record):
            raise AuditStoreError("Record hash is invalid")

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)

            if self.path.is_symlink():
                raise AuditStoreError(
                    "Symlink audit files are not allowed"
                )

            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW

            fd = os.open(self.path, flags, 0o600)

            try:
                # Restrict permissions on newly created or existing files.
                os.fchmod(fd, 0o600)

                payload = (
                    json.dumps(
                        asdict(record),
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    )
                    + "\n"
                ).encode("utf-8")

                with os.fdopen(fd, "ab") as handle:
                    fd = -1
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                if fd >= 0:
                    os.close(fd)

        except AuditStoreError:
            raise
        except OSError as exc:
            raise AuditStoreError("Unable to append audit record") from exc
