
"""Checkpoint anchors for JAS-SI audit-log integrity.

A checkpoint must be retained independently to provide a useful
anchor against rollback or full-file rewriting.
This module never executes actions.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Sequence

from jas_si_agent.audit_log import (
    GENESIS_HASH,
    AuditRecord,
    _calculate_hash,
)


_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class CheckpointError(ValueError):
    """Raised when a checkpoint is malformed or invalid."""


@dataclass(frozen=True)
class AuditCheckpoint:
    sequence: int
    head_hash: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or self.sequence < 0
        ):
            raise CheckpointError("sequence must be a non-negative integer")

        if not isinstance(self.head_hash, str) or not _HASH_PATTERN.fullmatch(
            self.head_hash
        ):
            raise CheckpointError("head_hash must be a lowercase SHA-256 hash")

        if self.sequence == 0 and self.head_hash != GENESIS_HASH:
            raise CheckpointError("empty checkpoint must use the genesis hash")

    def to_json(self) -> str:
        """Return canonical JSON suitable for independent retention."""
        return json.dumps(
            {
                "sequence": self.sequence,
                "head_hash": self.head_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, value: str) -> "AuditCheckpoint":
        """Parse a checkpoint without accepting extra or missing fields."""
        try:
            data = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise CheckpointError("Invalid checkpoint JSON") from exc

        if not isinstance(data, dict):
            raise CheckpointError("Checkpoint must be a JSON object")

        if set(data) != {"sequence", "head_hash"}:
            raise CheckpointError("Unexpected or missing checkpoint fields")

        return cls(
            sequence=data["sequence"],
            head_hash=data["head_hash"],
        )



def _validate_chain(records: Sequence[AuditRecord]) -> bool:
    """Validate record types, strict sequence numbers, and hash links."""
    previous_hash = GENESIS_HASH

    for expected_sequence, record in enumerate(records, start=1):
        if not isinstance(record, AuditRecord):
            return False

        # bool is a subclass of int, so reject it explicitly.
        if (
            not isinstance(record.sequence, int)
            or isinstance(record.sequence, bool)
            or record.sequence != expected_sequence
        ):
            return False

        if not isinstance(record.previous_hash, str):
            return False

        if not _HASH_PATTERN.fullmatch(record.previous_hash):
            return False

        if record.previous_hash != previous_hash:
            return False

        if not isinstance(record.record_hash, str):
            return False

        if not _HASH_PATTERN.fullmatch(record.record_hash):
            return False

        try:
            calculated_hash = _calculate_hash(record)
        except (TypeError, ValueError):
            return False

        if record.record_hash != calculated_hash:
            return False

        previous_hash = record.record_hash

    return True


def create_checkpoint(
    records: Sequence[AuditRecord],
) -> AuditCheckpoint:
    """Create an anchor for the current valid audit-log prefix."""
    if not _validate_chain(records):
        raise CheckpointError("Cannot checkpoint an invalid audit chain")

    if not records:
        return AuditCheckpoint(
            sequence=0,
            head_hash=GENESIS_HASH,
        )

    last_record = records[-1]
    return AuditCheckpoint(
        sequence=last_record.sequence,
        head_hash=last_record.record_hash,
    )


def verify_checkpoint(
    records: Sequence[AuditRecord],
    checkpoint: AuditCheckpoint,
) -> bool:
    """Verify chain integrity and that the checkpoint's prefix still exists.

    Records appended after the checkpoint are allowed.
    Truncation below the checkpoint or a changed anchored hash is rejected.
    """
    if not isinstance(checkpoint, AuditCheckpoint):
        return False

    if not _validate_chain(records):
        return False

    if checkpoint.sequence == 0:
        return checkpoint.head_hash == GENESIS_HASH

    if len(records) < checkpoint.sequence:
        return False

    anchored_record = records[checkpoint.sequence - 1]
    return anchored_record.record_hash == checkpoint.head_hash


def checkpoint_fingerprint(checkpoint: AuditCheckpoint) -> str:
    """Return a SHA-256 fingerprint for displaying or comparing an anchor."""
    return hashlib.sha256(checkpoint.to_json().encode("utf-8")).hexdigest()
