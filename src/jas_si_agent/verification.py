
"""JAS-SI MVP independent verification primitives.

This module evaluates reported outcomes against separately supplied
evidence. It does not collect evidence or execute actions.

A VERIFIED result means the supplied evidence meets this module's
checks; it does not prove that the evidence source is trustworthy.
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
    """Compare an action report with separately supplied evidence."""

    action_id = (
        report.action_id
        if isinstance(report.action_id, str)
        else ""
    )

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

    if evidence.collected_independently is not True:
        return inconclusive("INDEPENDENCE_NOT_ESTABLISHED")

    if evidence.observed_state == "success":
        if report.claimed_success:
            return VerificationResult(
                status=VerificationStatus.VERIFIED_SUCCESS,
                reason="REPORT_MATCHES_SUCCESS_EVIDENCE",
                action_id=action_id,
            )

        return VerificationResult(
            status=VerificationStatus.CONTRADICTED_REPORT,
            reason="EVIDENCE_SHOWS_SUCCESS_BUT_REPORT_DOES_NOT",
            action_id=action_id,
        )

    if evidence.observed_state == "failure":
        if report.claimed_success:
            return VerificationResult(
                status=VerificationStatus.FALSE_SUCCESS,
                reason="REPORT_CLAIMS_SUCCESS_BUT_EVIDENCE_SHOWS_FAILURE",
                action_id=action_id,
            )

        return VerificationResult(
            status=VerificationStatus.VERIFIED_FAILURE,
            reason="REPORT_MATCHES_FAILURE_EVIDENCE",
            action_id=action_id,
        )

    return inconclusive("UNKNOWN_OBSERVED_STATE")
