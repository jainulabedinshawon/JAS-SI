
"""Tamper-evident, in-memory audit records for the JAS-SI MVP.

This module records authorization decisions and verification outcomes.
It does not execute actions or provide durable storage.

A hash chain detects record modifications when verified against a
trusted checkpoint retained independently of this in-memory log.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from typing import Optional

from jas_si_agent.authorization import (
    ActionRequest,
    AuthorizationDecision,
)
from jas_si_agent.verification import VerificationResult


GENESIS_HASH = "0" * 64
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    action_id: str
    action_type: str
    resource: str
    authorized: bool
    authorization_reason: str
    grant_id: Optional[str]
    verification_status: str
    verification_reason: str
    evidence_ref: Optional[str]
    previous_hash: str
    record_hash: str


@dataclass(frozen=True)
class AuditCheckpoint:
    """A checkpoint that should be retained independently."""

    sequence: int
    record_hash: str


def _record_payload(record: AuditRecord) -> dict[str, object]:
    """Return the exact fields covered by the record hash."""
    payload = asdict(record)
    payload.pop("record_hash")
    return payload


def _calculate_hash(record: AuditRecord) -> str:
    """Calculate the SHA-256 hash of a canonical record payload."""
    canonical = json.dumps(
        _record_payload(record),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(canonical).hexdigest()


def _is_valid_hash(value: object) -> bool:
    """Return whether value is a lowercase, 64-character SHA-256 hex hash."""
    return (
        isinstance(value, str)
        and _HASH_PATTERN.fullmatch(value) is not None
    )


class AuditLog:
    """In-memory audit log with hash-chain integrity checks."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        """Expose an immutable snapshot of the current record list."""
        return tuple(self._records)

    def append(
        self,
        request: ActionRequest,
        decision: AuthorizationDecision,
        verification: VerificationResult,
        evidence_ref: Optional[str] = None,
    ) -> AuditRecord:
        """Append a decision/outcome record without executing anything."""

        if not isinstance(request, ActionRequest):
            raise TypeError("request must be an ActionRequest")

        if not isinstance(decision, AuthorizationDecision):
            raise TypeError("decision must be an AuthorizationDecision")

        if not isinstance(verification, VerificationResult):
            raise TypeError("verification must be a VerificationResult")

        if request.action_id != decision.action_id:
            raise ValueError("request and decision action IDs must match")

        if request.action_id != verification.action_id:
            raise ValueError(
                "request and verification action IDs must match"
            )

        if evidence_ref is not None and not isinstance(evidence_ref, str):
            raise TypeError("evidence_ref must be a string or None")

        grant_id = decision.grant_id

        if grant_id is not None and not isinstance(grant_id, str):
            raise TypeError("decision grant_id must be a string or None")

        previous_hash = (
            self._records[-1].record_hash
            if self._records
            else GENESIS_HASH
        )

        record = AuditRecord(
            sequence=len(self._records) + 1,
            action_id=request.action_id,
            action_type=request.action_type,
            resource=request.resource,
            authorized=decision.allowed,
            authorization_reason=decision.reason,
            grant_id=grant_id,
            verification_status=verification.status.value,
            verification_reason=verification.reason,
            evidence_ref=evidence_ref,
            previous_hash=previous_hash,
            record_hash="",
        )

        record = replace(
            record,
            record_hash=_calculate_hash(record),
        )

        self._records.append(record)
        return record

    def verify_integrity(
        self,
        checkpoint: Optional[AuditCheckpoint] = None,
    ) -> bool:
        """Verify the record chain and an optional trusted checkpoint."""

        expected_previous_hash = GENESIS_HASH

        for expected_sequence, record in enumerate(
            self._records,
            start=1,
        ):
            if not isinstance(record, AuditRecord):
                return False

            if (
                not isinstance(record.sequence, int)
                or isinstance(record.sequence, bool)
                or record.sequence != expected_sequence
            ):
                return False

            if not _is_valid_hash(record.previous_hash):
                return False

            if record.previous_hash != expected_previous_hash:
                return False

            if not _is_valid_hash(record.record_hash):
                return False

            try:
                calculated_hash = _calculate_hash(record)
            except (TypeError, ValueError, AttributeError):
                return False

            if record.record_hash != calculated_hash:
                return False

            expected_previous_hash = record.record_hash

        if checkpoint is None:
            return True

        if not isinstance(checkpoint, AuditCheckpoint):
            return False

        if (
            not isinstance(checkpoint.sequence, int)
            or isinstance(checkpoint.sequence, bool)
            or checkpoint.sequence < 0
        ):
            return False

        if not _is_valid_hash(checkpoint.record_hash):
            return False

        if checkpoint.sequence == 0:
            return checkpoint.record_hash == GENESIS_HASH

        if checkpoint.sequence > len(self._records):
            return False

        anchored_record = self._records[checkpoint.sequence - 1]

        return anchored_record.record_hash == checkpoint.record_hash

    def create_checkpoint(self) -> AuditCheckpoint:
        """Create a checkpoint to retain outside this in-memory log."""

        if not self.verify_integrity():
            raise ValueError(
                "cannot create checkpoint for an invalid audit log"
            )

        if not self._records:
            return AuditCheckpoint(
                sequence=0,
                record_hash=GENESIS_HASH,
            )

        last_record = self._records[-1]

        return AuditCheckpoint(
            sequence=last_record.sequence,
            record_hash=last_record.record_hash,
        )
