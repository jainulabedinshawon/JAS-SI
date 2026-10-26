"""JAS-SI REST API with API-key authentication and rate limiting.

The API evaluates authorization and verifies reported outcomes. It does not execute actions.

The in-memory rate limiter is per process and is not a distributed limiter.
"""

from __future__ import annotations

import hmac
import threading
import time
from collections import defaultdict, deque
from math import ceil
from typing import Deque, Dict, Optional

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Security,
)
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
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
        "Authorization evaluation and outcome verification only. "
        "This API does not execute actions. "
        "Protected endpoints require the X-API-Key header. "
        "Versioned API routes have a per-process rate limit."
    ),
)

api_key_header = APIKeyHeader(
    name="X-API-Key",
    scheme_name="ApiKeyAuth",
    description="Provide the configured JAS-SI API key.",
    auto_error=False,
)

# Deliberately no action executor is registered.
_sdk = JASSI()

# Sliding-window timestamps, keyed by client IP.
_rate_limit_buckets: Dict[str, Deque[float]] = defaultdict(deque)
_rate_limit_lock = threading.Lock()


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


def _rate_limit_decision(client_ip: str):
    """Return allowed, remaining, and retry-after seconds."""
    now = time.monotonic()
    limit = settings.rate_limit_requests
    window = settings.rate_limit_window_seconds

    with _rate_limit_lock:
        bucket = _rate_limit_buckets[client_ip]
        while bucket and now - bucket[0] >= window:
            bucket.popleft()
        if len(bucket) >= limit:
            retry_after = max(
                1,
                ceil(window - (now - bucket[0])),
            )
            return False, 0, retry_after
        bucket.append(now)
        remaining = max(0, limit - len(bucket))
        return True, remaining, 0


@app.middleware("http")
async def security_and_rate_limit_middleware(
    request: Request,
    call_next,
):
    """Apply baseline security headers and rate-limit /v1/ routes."""
    if request.url.path.startswith("/v1/"):
        client_ip = (
            request.client.host if request.client is not None else "unknown"
        )
        allowed, remaining, retry_after = _rate_limit_decision(client_ip)
        if not allowed:
            response = JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(settings.rate_limit_requests),
                    "X-RateLimit-Remaining": "0",
                },
            )
        else:
            response = await call_next(request)
            response.headers["X-RateLimit-Limit"] = str(
                settings.rate_limit_requests
            )
            response.headers["X-RateLimit-Remaining"] = str(remaining)
    else:
        response = await call_next(request)

    # Attach baseline security headers to every response (including 429 errors)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    return response


def _require_enabled() -> None:
    if not settings.api_enabled:
        raise HTTPException(
            status_code=503,
            detail="JAS-SI API is disabled by configuration",
        )


def _require_api_key(
    x_api_key: Optional[str] = Security(api_key_header),
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
    if not hmac.compare_digest(
        x_api_key.encode("utf-8"),
        configured_key.encode("utf-8"),
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
