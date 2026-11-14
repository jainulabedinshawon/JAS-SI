"""JAS-SI outcome verification primitives.

This module validates report/evidence shape and action binding. It does not
collect evidence, authenticate its provenance, or execute actions.

Caller-supplied evidence is always untrusted. Until a server-side trusted
collector is integrated, the verifier MUST return INCONCLUSIVE for otherwise
well-formed evidence. A caller-controlled Boolean cannot establish provenance.
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
    # Compatibility-only caller claim. This field is NEVER trusted.
    # Only a future authenticated server-side collector may establish provenance.
    collected_independently: bool = False


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    reason: str
    action_id: str


def verify_report(
    report: ActionReport,
    evidence: VerificationEvidence | None,
) -> VerificationResult:
    """Validate evidence shape, but fail closed without trusted provenance."""

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

    if evidence.observed_state not in {"success", "failure"}:
        return inconclusive("UNKNOWN_OBSERVED_STATE")

    # Critical trust boundary: collected_independently is supplied by the
    # caller and therefore cannot authenticate how evidence was collected.
    # Do not emit VERIFIED_* or FALSE_SUCCESS until a trusted collector
    # independently retrieves and validates the evidence source.
    return inconclusive("TRUSTED_EVIDENCE_COLLECTOR_NOT_CONFIGURED")
