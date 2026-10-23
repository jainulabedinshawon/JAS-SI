
"""Tamper-evident, in-memory audit records for the JAS-SI MVP.

This module records decisions and verification outcomes.
It does not execute actions or provide durable storage.
A hash chain can reveal modifications when checked against a
trusted, independently retained checkpoint.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from typing import Optional

from jas_si_agent.authorization import (
    ActionRequest,
    AuthorizationDecision,
)
from jas_si_agent.verification import VerificationResult


GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    action_id: str
    action_type: str
    resource: str
    authorized: bool
    authorization_reason: str
    verification_status: str
    verification_reason: str
    evidence_ref: Optional[str]
    previous_hash: str
    record_hash: str


def _record_payload(record: AuditRecord) -> dict[str, object]:
    """Return the exact fields covered by the record hash."""
    payload = asdict(record)
    payload.pop("record_hash")
    return payload


def _calculate_hash(record: AuditRecord) -> str:
    canonical = json.dumps(
        _record_payload(record),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(canonical).hexdigest()


class AuditLog:
    """Append-only interface with hash-chain integrity checks."""

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
            raise ValueError("request and verification action IDs must match")

        if evidence_ref is not None and not isinstance(evidence_ref, str):
            raise TypeError("evidence_ref must be a string or None")

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

    def verify_integrity(self) -> bool:
        """Check sequence, hash values, and links between records."""

        expected_previous_hash = GENESIS_HASH

        for expected_sequence, record in enumerate(self._records, start=1):
            if record.sequence != expected_sequence:
                return False

            if record.previous_hash != expected_previous_hash:
                return False

            if record.record_hash != _calculate_hash(record):
                return False

            expected_previous_hash = record.record_hash

        return True
