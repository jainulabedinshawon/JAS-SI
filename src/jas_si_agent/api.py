"""JAS-SI REST API scaffold.

This API evaluates authorization and compares reports with evidence.
It does not execute actions. Do not expose publicly before security review.
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from jas_si_agent.config import Settings
from jas_si_agent.sdk import JASSI
from jas_si_agent.verification import (
    ActionReport,
    VerificationEvidence,
)

settings = Settings.from_env()
app = FastAPI(
    title=settings.service_name,
    version="0.1.0",
    description="Authorization evaluation and outcome verification only.",
)

# Deliberately no action executor is registered.
_sdk = JASSI()

class AuthorizeRequest(BaseModel):
    action_id: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=1024)

class VerifyRequest(BaseModel):
    action_id: str = Field(min_length=1, max_length=128)
    claimed_success: bool
    observed_state: Optional[str] = Field(
        default=None, max_length=256
    )
    evidence_ref: Optional[str] = Field(
        default=None, max_length=2048
    )
    collected_independently: bool = False

def _require_enabled() -> None:
    if not settings.api_enabled:
        raise HTTPException(
            status_code=503,
            detail="JAS-SI API is disabled by configuration",
        )

@app.get("/health")
def health() -> dict:
    """Non-sensitive liveness endpoint."""
    return {
        "service": settings.service_name,
        "status": "ok",
        "api_enabled": settings.api_enabled,
    }

@app.post("/v1/authorize")
def authorize(payload: AuthorizeRequest) -> dict:
    _require_enabled()

    try:
        decision = _sdk.authorize(
            action_id=payload.action_id,
            action=payload.action,
            resource=payload.resource,
        )
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Authorization evaluation unavailable",
        )

    return {
        "action_id": decision.action_id,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "grant_id": decision.grant_id,
        "executed": False,
    }

@app.post("/v1/verify")
def verify(payload: VerifyRequest) -> dict:
    _require_enabled()

    report = ActionReport(
        action_id=payload.action_id,
        claimed_success=payload.claimed_success,
    )

    evidence = None
    if (
        payload.observed_state is not None
        or payload.evidence_ref is not None
        or payload.collected_independently
    ):
        if not payload.observed_state or not payload.evidence_ref:
            raise HTTPException(
                status_code=422,
                detail=(
                    "observed_state and evidence_ref must both be "
                    "provided when evidence is supplied"
                ),
            )

        evidence = VerificationEvidence(
            action_id=payload.action_id,
            observed_state=payload.observed_state,
            evidence_ref=payload.evidence_ref,
            collected_independently=payload.collected_independently,
        )

    try:
        result = _sdk.verify(report, evidence)
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Outcome verification unavailable",
        )

    status = getattr(result.status, "value", result.status)
    return {
        "action_id": result.action_id,
        "status": status,
        "reason": result.reason,
    }
