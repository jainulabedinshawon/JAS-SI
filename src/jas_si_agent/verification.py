"""JAS-SI verification primitives.

Caller-submitted evidence is not independently trusted. This module does
not collect evidence, authenticate its origin, or execute actions. Until a
trusted server-side collector establishes provenance, supplied evidence
must never produce a verified outcome.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class VerificationStatus(str, Enum):
    VERIFIED_SUCCESS = "VERIFIED_SUCCESS"
    VERIFIED_FAILURE = "VERIFIED_FAILURE"
    FALSE_SUCCESS = "FALSE_SUCCESS"
    CONTRADICTED_REPORT = "CONTRADICTED_REPORT"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class ActionReport:
    action_id: str
    claimed_success: bool


@dataclass(frozen=True)
class VerificationEvidence:
    action_id: str
    observed_state: str
    evidence_ref: str
    # Deprecated compatibility field. It is caller-controlled and is never
    # accepted as proof of independent collection.
    collected_independently: bool


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    reason: str
    action_id: str


def verify_report(
    report: ActionReport,
    evidence: VerificationEvidence | None,
) -> VerificationResult:
    """Validate input shape, but fail closed without authenticated provenance."""

    if not isinstance(report, ActionReport):
        return VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            reason="INVALID_ACTION_REPORT",
            action_id="",
        )

    action_id = report.action_id if isinstance(report.action_id, str) else ""

    def inconclusive(reason: str) -> VerificationResult:
        return VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            reason=reason,
            action_id=action_id,
        )

    if not action_id.strip():
        return inconclusive("INVALID_ACTION_ID")

    if not isinstance(report.claimed_success, bool):
        return inconclusive("INVALID_SUCCESS_CLAIM")

    if evidence is None:
        return inconclusive("EVIDENCE_MISSING")

    if not isinstance(evidence, VerificationEvidence):
        return inconclusive("INVALID_EVIDENCE_OBJECT")

    if not isinstance(evidence.action_id, str):
        return inconclusive("INVALID_EVIDENCE_ACTION_ID")

    if evidence.action_id != action_id:
        return inconclusive("EVIDENCE_ACTION_ID_MISMATCH")

    if not isinstance(evidence.evidence_ref, str):
        return inconclusive("INVALID_EVIDENCE_REFERENCE")

    if not evidence.evidence_ref.strip():
        return inconclusive("EVIDENCE_REFERENCE_MISSING")

    # Neither a caller-provided Boolean nor an evidence reference authenticates
    # provenance. No trusted collector is currently wired into this function.
    return inconclusive("TRUSTED_EVIDENCE_PROVENANCE_UNAVAILABLE")
