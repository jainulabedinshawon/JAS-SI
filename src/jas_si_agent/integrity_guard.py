
"""Fail-closed startup verification for persisted JAS-SI audit state.

This module checks the audit log against its saved checkpoint.
It does not execute actions or grant authorization.
"""

from __future__ import annotations

from dataclasses import dataclass

from jas_si_agent.audit_store import (
    AuditStoreError,
    JsonlAuditStore,
)
from jas_si_agent.checkpoint_store import (
    CheckpointStoreError,
    JsonCheckpointStore,
)


@dataclass(frozen=True)
class IntegrityCheckResult:
    valid: bool
    reason: str
    record_count: int
    checkpoint_sequence: int | None


def verify_startup_integrity(
    audit_store: JsonlAuditStore,
    checkpoint_store: JsonCheckpointStore,
) -> IntegrityCheckResult:
    """Require a valid audit chain and a checkpoint for its current head.

    A missing, stale, malformed, or inconsistent checkpoint fails closed.
    This is a local consistency check, not proof of independent trust.
    """
    try:
        records = audit_store.load_records()
    except AuditStoreError:
        return IntegrityCheckResult(
            valid=False,
            reason="AUDIT_LOG_INVALID_OR_UNREADABLE",
            record_count=0,
            checkpoint_sequence=None,
        )

    try:
        checkpoint = checkpoint_store.load()
    except CheckpointStoreError:
        return IntegrityCheckResult(
            valid=False,
            reason="CHECKPOINT_MISSING_OR_INVALID",
            record_count=len(records),
            checkpoint_sequence=None,
        )

    if checkpoint.sequence != len(records):
        return IntegrityCheckResult(
            valid=False,
            reason="CHECKPOINT_NOT_AT_CURRENT_LOG_HEAD",
            record_count=len(records),
            checkpoint_sequence=checkpoint.sequence,
        )

    if not checkpoint_store.verify_records(records):
        return IntegrityCheckResult(
            valid=False,
            reason="CHECKPOINT_VERIFICATION_FAILED",
            record_count=len(records),
            checkpoint_sequence=checkpoint.sequence,
        )

    return IntegrityCheckResult(
        valid=True,
        reason="AUDIT_LOG_AND_CHECKPOINT_VERIFIED",
        record_count=len(records),
        checkpoint_sequence=checkpoint.sequence,
    )
