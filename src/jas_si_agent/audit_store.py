
"""Durable JSONL storage for JAS-SI audit records.

This module persists and validates audit records. It does not execute actions.

The store validates record types, sequences, and the SHA-256 hash chain.
Use one writer at a time. A local hash chain is not a tamper-proof remote
audit service and does not replace an independently trusted checkpoint.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import asdict
from pathlib import Path
from typing import Any

from jas_si_agent.audit_log import (
    GENESIS_HASH,
    AuditRecord,
    _calculate_hash,
)


_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")

_EXPECTED_FIELDS = {
    "sequence",
    "action_id",
    "action_type",
    "resource",
    "authorized",
    "authorization_reason",
    "grant_id",
    "verification_status",
    "verification_reason",
    "evidence_ref",
    "previous_hash",
    "record_hash",
}


class AuditStoreError(ValueError):
    """Raised when audit storage or validation fails."""


def _require_string(
    value: object,
    field_name: str,
    *,
    allow_empty: bool = False,
) -> None:
    """Validate a string field without coercing its value."""
    if not isinstance(value, str):
        raise AuditStoreError(
            f"{field_name} must be a string"
        )

    if not allow_empty and not value.strip():
        raise AuditStoreError(
            f"{field_name} must not be empty"
        )


def _validate_record_fields(record: AuditRecord) -> None:
    """Validate all record fields and reject Python bool/int confusion."""
    if not isinstance(record, AuditRecord):
        raise AuditStoreError(
            "Record must be an AuditRecord"
        )

    if (
        not isinstance(record.sequence, int)
        or isinstance(record.sequence, bool)
        or record.sequence < 1
    ):
        raise AuditStoreError(
            "sequence must be a positive integer"
        )

    _require_string(record.action_id, "action_id")
    _require_string(record.action_type, "action_type")
    _require_string(record.resource, "resource")
    _require_string(
        record.authorization_reason,
        "authorization_reason",
    )
    _require_string(
        record.verification_status,
        "verification_status",
    )
    _require_string(
        record.verification_reason,
        "verification_reason",
    )

    if not isinstance(record.authorized, bool):
        raise AuditStoreError(
            "authorized must be a boolean"
        )

    if record.grant_id is not None:
        _require_string(record.grant_id, "grant_id")

    if record.evidence_ref is not None:
        _require_string(
            record.evidence_ref,
            "evidence_ref",
        )

    for field_name in ("previous_hash", "record_hash"):
        value = getattr(record, field_name)

        if (
            not isinstance(value, str)
            or _HASH_PATTERN.fullmatch(value) is None
        ):
            raise AuditStoreError(
                f"{field_name} must be a lowercase SHA-256 hash"
            )


def _record_from_json(data: Any, line_number: int) -> AuditRecord:
    """Build one record only when its schema and values are valid."""
    if not isinstance(data, dict):
        raise AuditStoreError(
            f"Record at line {line_number} must be a JSON object"
        )

    if set(data) != _EXPECTED_FIELDS:
        raise AuditStoreError(
            f"Unexpected or missing fields at line {line_number}"
        )

    try:
        record = AuditRecord(**data)
    except (TypeError, ValueError) as exc:
        raise AuditStoreError(
            f"Invalid record fields at line {line_number}"
        ) from exc

    try:
        _validate_record_fields(record)
    except AuditStoreError as exc:
        raise AuditStoreError(
            f"Invalid record at line {line_number}: {exc}"
        ) from exc

    return record


def _validate_record_hash(record: AuditRecord) -> None:
    """Reject records whose canonical payload does not match its hash."""
    try:
        calculated_hash = _calculate_hash(record)
    except (TypeError, ValueError, AttributeError) as exc:
        raise AuditStoreError(
            "Unable to calculate audit record hash"
        ) from exc

    if record.record_hash != calculated_hash:
        raise AuditStoreError(
            "Audit record hash mismatch"
        )


class JsonlAuditStore:
    """Append-only JSONL store with strict hash-chain validation."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _reject_symlink(self) -> None:
        """Reject a symbolic link, including a dangling symbolic link."""
        try:
            if self.path.is_symlink():
                raise AuditStoreError(
                    "Symlink audit files are not allowed"
                )
        except OSError as exc:
            raise AuditStoreError(
                "Unable to inspect audit file path"
            ) from exc

    def load_records(self) -> tuple[AuditRecord, ...]:
        """Load every record and validate its schema, order, and hash chain."""
        self._reject_symlink()

        try:
            if not self.path.exists():
                return ()

            # Refuse non-regular files such as FIFOs and device files.
            if not stat.S_ISREG(self.path.stat().st_mode):
                raise AuditStoreError(
                    "Audit path must be a regular file"
                )

            records: list[AuditRecord] = []
            expected_previous_hash = GENESIS_HASH

            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        raise AuditStoreError(
                            f"Blank record at line {line_number}"
                        )

                    try:
                        data: Any = json.loads(line)
                    except (json.JSONDecodeError, RecursionError) as exc:
                        raise AuditStoreError(
                            f"Invalid JSON at line {line_number}"
                        ) from exc

                    record = _record_from_json(data, line_number)

                    expected_sequence = len(records) + 1
                    if record.sequence != expected_sequence:
                        raise AuditStoreError(
                            f"Invalid sequence at line {line_number}"
                        )

                    if record.previous_hash != expected_previous_hash:
                        raise AuditStoreError(
                            f"Broken hash chain at line {line_number}"
                        )

                    _validate_record_hash(record)

                    records.append(record)
                    expected_previous_hash = record.record_hash

            return tuple(records)

        except AuditStoreError:
            raise
        except (OSError, UnicodeError, RecursionError) as exc:
            raise AuditStoreError(
                "Unable to read or decode audit file"
            ) from exc

    def append(self, record: AuditRecord) -> None:
        """Validate and durably append one record to the current chain.

        This method assumes a single writer. It does not provide cross-process
        locking or atomic coordination with a separate checkpoint store.
        """
        _validate_record_fields(record)
        _validate_record_hash(record)

        existing = self.load_records()

        expected_sequence = len(existing) + 1
        expected_previous_hash = (
            existing[-1].record_hash if existing else GENESIS_HASH
        )

        if record.sequence != expected_sequence:
            raise AuditStoreError(
                "Unexpected record sequence"
            )

        if record.previous_hash != expected_previous_hash:
            raise AuditStoreError(
                "Record does not extend the current chain"
            )

        payload = (
            json.dumps(
                asdict(record),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")

        fd = -1

        try:
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            # Check again after directory creation.
            self._reject_symlink()

            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND

            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW

            fd = os.open(
                self.path,
                flags,
                0o600,
            )

            # Confirm the opened descriptor refers to a regular file.
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise AuditStoreError(
                    "Audit path must be a regular file"
                )

            # Restrict permissions where the platform supports fchmod.
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)

            with os.fdopen(fd, "ab") as handle:
                fd = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())

        except AuditStoreError:
            raise
        except (OSError, UnicodeError, ValueError) as exc:
            raise AuditStoreError(
                "Unable to append audit record"
            ) from exc
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
