
"""JAS-SI REST API scaffold.

The API evaluates authorization and verifies reported outcomes.
It does not execute actions.

Do not expose publicly before a complete security review.
"""

from __future__ import annotations

import hmac
from typing import Optional

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
)
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
    description=(
        "Authorization evaluation and outcome verification only."
    ),
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
        default=None,
        max_length=256,
    )
    evidence_ref: Optional[str] = Field(
        default=None,
        max_length=2048,
    )
    collected_independently: bool = False


def _require_enabled() -> None:
    if not settings.api_enabled:
        raise HTTPException(
            status_code=503,
            detail="JAS-SI API is disabled by configuration",
        )


def _require_api_key(
    x_api_key: Optional[str] = Header(
        default=None,
        alias="X-API-Key",
    ),
) -> None:
    """Fail closed when the API or its authentication is misconfigured."""

    _require_enabled()

    configured_key = settings.api_key

    if not configured_key:
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured",
        )

    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    provided_bytes = x_api_key.encode("utf-8")
    configured_bytes = configured_key.encode("utf-8")

    if not hmac.compare_digest(
        provided_bytes,
        configured_bytes,
    ):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


@app.get("/health")
def health() -> dict:
    """Public liveness endpoint; never return secret configuration."""
    return {
        "service": settings.service_name,
        "status": "ok",
        "api_enabled": settings.api_enabled,
    }


@app.post(
    "/v1/authorize",
    dependencies=[Depends(_require_api_key)],
)
def authorize(payload: AuthorizeRequest) -> dict:
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
        ) from None

    return {
        "action_id": decision.action_id,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "grant_id": decision.grant_id,
        "executed": False,
    }


@app.post(
    "/v1/verify",
    dependencies=[Depends(_require_api_key)],
)
def verify(payload: VerifyRequest) -> dict:
    report = ActionReport(
        action_id=payload.action_id,
        claimed_success=payload.claimed_success,
    )

    evidence = None

    evidence_submitted = (
        payload.observed_state is not None
        or payload.evidence_ref is not None
        or payload.collected_independently
    )

    if evidence_submitted:
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
        ) from None

    status = getattr(result.status, "value", result.status)

    return {
        "action_id": result.action_id,
        "status": status,
        "reason": result.reason,
    }
