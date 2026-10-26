
"""JAS-SI REST API with authentication, rate limiting, and security logging.

The API evaluates authorization and verifies reported outcomes.
It does not execute actions.

The in-memory rate limiter is per process, not distributed.
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
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

# Dependency-free JSON logging. Do not log secrets or request bodies.
logger = logging.getLogger("jas_si.security")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)


def _log_security_event(
    event_type: str,
    request: Optional[Request] = None,
    **details,
) -> None:
    """Write a single JSON security event without affecting API behavior."""
    try:
        payload = dict(details)

        # Reserved fields are assigned last so details cannot override them.
        payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        payload["event_type"] = event_type

        if request is not None:
            payload["request_id"] = getattr(
                request.state, "request_id", "unknown"
            )
            payload["method"] = request.method
            payload["endpoint"] = request.url.path

        logger.info(
            json.dumps(payload, separators=(",", ":"), sort_keys=True)
        )
    except Exception:
        # Logging failure must not change authorization or verification.
        pass


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
    """Add a server-generated request ID, security headers, and rate limits."""
    request.state.request_id = uuid.uuid4().hex

    if request.url.path.startswith("/v1/"):
        client_ip = (
            request.client.host if request.client is not None else "unknown"
        )
        allowed, remaining, retry_after = _rate_limit_decision(client_ip)

        if not allowed:
            _log_security_event(
                "rate_limit_exceeded",
                request,
                status_code=429,
                reason_code="rate_limit_exceeded",
                retry_after_seconds=retry_after,
            )
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

    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    return response


def _require_enabled(request: Request) -> None:
    if not settings.api_enabled:
        _log_security_event(
            "configuration_error",
            request,
            status_code=503,
            reason_code="api_disabled",
        )
        raise HTTPException(
            status_code=503,
            detail="JAS-SI API is disabled by configuration",
        )


def _require_api_key(
    request: Request,
    x_api_key: Optional[str] = Security(api_key_header),
) -> None:
    """Fail closed when API or authentication configuration is invalid."""
    _require_enabled(request)

    configured_key = settings.api_key
    if not configured_key:
        _log_security_event(
            "configuration_error",
            request,
            status_code=503,
            reason_code="api_key_not_configured",
        )
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured",
        )

    if not x_api_key:
        _log_security_event(
            "authentication_failure",
            request,
            status_code=401,
            reason_code="missing_api_key",
        )
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if not hmac.compare_digest(
        x_api_key.encode("utf-8"),
        configured_key.encode("utf-8"),
    ):
        _log_security_event(
            "authentication_failure",
            request,
            status_code=401,
            reason_code="invalid_api_key",
        )
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
def authorize(payload: AuthorizeRequest, request: Request) -> dict:
    try:
        decision = _sdk.authorize(
            action_id=payload.action_id,
            action=payload.action,
            resource=payload.resource,
        )
    except Exception:
        _log_security_event(
            "authorization_error",
            request,
            status_code=503,
            reason_code="evaluation_unavailable",
        )
        raise HTTPException(
            status_code=503,
            detail="Authorization evaluation unavailable",
        ) from None

    _log_security_event(
        "authorization_evaluated",
        request,
        status_code=200,
        action_id=decision.action_id,
        allowed=bool(decision.allowed),
        reason_code="allowed" if decision.allowed else "denied",
    )

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
def verify(payload: VerifyRequest, request: Request) -> dict:
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
            _log_security_event(
                "verification_input_rejected",
                request,
                status_code=422,
                reason_code="incomplete_evidence",
            )
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
        _log_security_event(
            "verification_error",
            request,
            status_code=503,
            reason_code="verification_unavailable",
        )
        raise HTTPException(
            status_code=503,
            detail="Outcome verification unavailable",
        ) from None

    status = getattr(result.status, "value", result.status)

    _log_security_event(
        "outcome_verified",
        request,
        status_code=200,
        action_id=result.action_id,
        verification_status=str(status)[:64],
    )

    return {
        "action_id": result.action_id,
        "status": status,
        "reason": result.reason,
    }
