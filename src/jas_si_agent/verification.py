"""JAS-SI evidence comparison and fail-closed verification primitives.

This module does not execute actions or collect evidence. Caller-supplied
evidence can be compared with a report, but cannot establish its own
provenance. A VERIFIED status is therefore unavailable until a trusted,
server-side evidence attestation is integrated.
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


class EvidenceConsistencyStatus(str, Enum):
    MATCHED_SUCCESS = "MATCHED_SUCCESS"
    MATCHED_FAILURE = "MATCHED_FAILURE"
    FALSE_SUCCESS_CANDIDATE = "FALSE_SUCCESS_CANDIDATE"
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


@dataclass(frozen=True)
class EvidenceConsistency:
    status: EvidenceConsistencyStatus
    reason: str
    action_id: str


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    reason: str
    action_id: str
    evidence_consistency: EvidenceConsistencyStatus | None = None


def compare_report_to_evidence(
    report: ActionReport,
    evidence: VerificationEvidence | None,
) -> EvidenceConsistency:
    """Compare claims with submitted evidence without asserting source trust."""
    if not isinstance(report, ActionReport):
        return EvidenceConsistency(
            EvidenceConsistencyStatus.INCONCLUSIVE,
            "INVALID_ACTION_REPORT",
            "",
        )

    action_id = report.action_id if isinstance(report.action_id, str) else ""

    def inconclusive(reason: str) -> EvidenceConsistency:
        return EvidenceConsistency(
            EvidenceConsistencyStatus.INCONCLUSIVE,
            reason,
            action_id,
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
    if not isinstance(evidence.observed_state, str):
        return inconclusive("INVALID_OBSERVED_STATE")

    if evidence.observed_state == "success":
        if report.claimed_success:
            return EvidenceConsistency(
                EvidenceConsistencyStatus.MATCHED_SUCCESS,
                "REPORT_MATCHES_SUBMITTED_SUCCESS_EVIDENCE",
                action_id,
            )
        return EvidenceConsistency(
            EvidenceConsistencyStatus.CONTRADICTED_REPORT,
            "SUBMITTED_EVIDENCE_SHOWS_SUCCESS_BUT_REPORT_DOES_NOT",
            action_id,
        )

    if evidence.observed_state == "failure":
        if report.claimed_success:
            return EvidenceConsistency(
                EvidenceConsistencyStatus.FALSE_SUCCESS_CANDIDATE,
                "REPORT_CLAIMS_SUCCESS_BUT_SUBMITTED_EVIDENCE_SHOWS_FAILURE",
                action_id,
            )
        return EvidenceConsistency(
            EvidenceConsistencyStatus.MATCHED_FAILURE,
            "REPORT_MATCHES_SUBMITTED_FAILURE_EVIDENCE",
            action_id,
        )

    return inconclusive("UNKNOWN_OBSERVED_STATE")


def verify_report(
    report: ActionReport,
    evidence: VerificationEvidence | None,
) -> VerificationResult:
    """Fail closed: submitted evidence is not independently attested here."""
    comparison = compare_report_to_evidence(report, evidence)

    if comparison.status == EvidenceConsistencyStatus.INCONCLUSIVE:
        return VerificationResult(
            status=VerificationStatus.INCONCLUSIVE,
            reason=comparison.reason,
            action_id=comparison.action_id,
        )

    return VerificationResult(
        status=VerificationStatus.INCONCLUSIVE,
        reason="EVIDENCE_PROVENANCE_UNVERIFIED",
        action_id=comparison.action_id,
        evidence_consistency=comparison.status,
    )
