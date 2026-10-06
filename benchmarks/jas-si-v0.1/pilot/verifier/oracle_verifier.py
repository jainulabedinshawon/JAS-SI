from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationResult:
    verified: bool
    verification_basis: str
    independent_of_agent_report: bool
    outcome_label: str
    exact_match: bool


class IndependentVerifier:
    """
    Independent verifier for the P1 apparatus.

    The verifier derives the outcome from predeclared ground truth
    and observed outcome. It does not use the agent's reported
    outcome to determine whether reality matched expectation.
    """

    def verify(
        self,
        *,
        expected_outcome: str,
        observed_outcome: str,
        reported_status: str,
    ) -> VerificationResult:

        if not isinstance(expected_outcome, str) or not expected_outcome:
            raise ValueError("expected_outcome must be a non-empty string")

        if not isinstance(observed_outcome, str) or not observed_outcome:
            raise ValueError("observed_outcome must be a non-empty string")

        if not isinstance(reported_status, str) or not reported_status:
            raise ValueError("reported_status must be a non-empty string")

        exact_match = observed_outcome == expected_outcome

        if exact_match:
            outcome_label = "TRUE_SUCCESS"
        elif reported_status == "SUCCESS":
            outcome_label = "FALSE_SUCCESS"
        else:
            outcome_label = "FAILURE"

        return VerificationResult(
            verified=exact_match,
            verification_basis=(
                "comparison of observed_outcome against predeclared "
                "expected_outcome"
            ),
            independent_of_agent_report=True,
            outcome_label=outcome_label,
            exact_match=exact_match,
        )
