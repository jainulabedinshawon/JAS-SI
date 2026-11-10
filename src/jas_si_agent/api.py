"""JAS-SI REST API with authentication, rate limiting, and security logging.

The API evaluates authorization and verifies reported outcomes.
It does not execute actions.

The security event store is injected through FastAPI application state.
Critical operation results are withheld when their audit event cannot
be persisted. Authentication denials remain denials even if logging fails.

The in-memory rate limiter is per process, not distributed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Deque, Dict, Optional

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Security,
)
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from jas_si_agent.config import Settings
from jas_si_agent.dashboard import DASHBOARD_HTML
from jas_si_agent.demo import DEMO_HTML
from jas_si_agent.live_demo import LIVE_GITHUB_DEMO_HTML
from jas_si_agent.api_key_registry import PostgresApiKeyRegistry
from jas_si_agent.usage_meter import PostgresUsageMeter
from jas_si_agent.sdk import JASSI
from jas_si_agent.postgres_security_event_store import (
    PostgresSecurityEventStore,
)
from jas_si_agent.security_event_store import JsonlSecurityEventStore
from jas_si_agent.security_event_store_interface import SecurityEventStore
from jas_si_agent.verification import ActionReport, VerificationEvidence
from jas_si_agent.verify_router import router as github_verify_router


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

# Default backend. Tests and deployments can replace this through app.state.
app.state.security_event_store = JsonlSecurityEventStore(
    settings.security_event_log_path
)


@app.on_event("startup")
def initialize_security_event_store() -> None:
    """Require verified PostgreSQL audit and API-key registries in deployed environments."""

    if settings.environment not in {"preview", "production"}:
        return

    if not settings.api_enabled:
        raise RuntimeError("Preview/production requires API enabled")
    if not settings.api_key_pepper:
        raise RuntimeError("Preview/production requires JAS_SI_API_KEY_PEPPER")
    if not settings.database_url:
        raise RuntimeError("Preview/production requires JAS_SI_DATABASE_URL")

    store = PostgresSecurityEventStore(settings.database_url)
    try:
        result = store.verify_integrity()
    except Exception as exc:
        raise RuntimeError(
            "PostgreSQL audit integrity verification failed; startup denied"
        ) from exc

    if result.get("valid") is not True:
        raise RuntimeError(
            "PostgreSQL audit chain is not valid; startup denied"
        )

    try:
        registry = PostgresApiKeyRegistry(
            settings.database_url,
            settings.api_key_pepper,
        )
        if not registry.verify_schema():
            raise RuntimeError("API key registry schema is not installed")
    except Exception as exc:
        raise RuntimeError(
            "API key registry readiness check failed; startup denied"
        ) from exc

    app.state.security_event_store = store

    # Metering is prepared without running a migration at startup.
    # The approved database migration must precede production deployment.
    app.state.usage_meter = PostgresUsageMeter(settings.database_url)

def get_security_event_store(request: Request) -> SecurityEventStore:
    """Return the storage backend configured for this application."""
    store = getattr(request.app.state, "security_event_store", None)

    if store is None:
        raise HTTPException(
            status_code=503,
            detail="Security event storage is not configured",
        )

    return store


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
    event_store: Optional[SecurityEventStore] = None,
    **details,
) -> bool:
    """Persist a sanitized event and return whether persistence succeeded.

    Stdout logging is supplementary. A successful stdout write is never
    treated as proof that the durable event store accepted the event.
    """
    try:
        payload = dict(details)

        # Reserved fields cannot be overridden by caller-supplied details.
        payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        payload["event_type"] = event_type

        if request is not None:
            for state_field in ("tenant_id", "api_key_id"):
                state_value = getattr(request.state, state_field, None)
                if state_value is not None:
                    payload[state_field] = state_value
            payload["request_id"] = getattr(
                request.state,
                "request_id",
                "unknown",
            )
            payload["method"] = request.method
            payload["endpoint"] = request.url.path

        if event_store is None and request is not None:
            event_store = getattr(
                request.app.state,
                "security_event_store",
                None,
            )

        if event_store is None:
            persisted = False
        else:
            try:
                event_store.append(payload)
                persisted = True
            except Exception:
                persisted = False

        if not persisted:
            failure_payload = {
                "event_type": "security_event_persistence_failure",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": payload.get("request_id", "unknown"),
            }
            try:
                logger.error(
                    json.dumps(
                        failure_payload,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )
            except Exception:
                pass

        # Stdout is useful for diagnostics but is not the audit record.
        try:
            logger.info(
                json.dumps(
                    payload,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        except Exception:
            pass

        return persisted

    except Exception:
        # A logging failure must never bypass an authentication denial.
        return False


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
        idempotency_key = request.headers.get("Idempotency-Key")
        metered_paths = {
            "/v1/authorize": "authorization.evaluate",
            "/v1/verify": "outcome.submit",
            "/v1/github/evidence": "github.evidence.verify",
        }
        operation = metered_paths.get(request.url.path)
        meter = getattr(request.app.state, "usage_meter", None)

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
        elif (
            operation is not None
            and meter is not None
            and idempotency_key is None
        ):
            response = JSONResponse(
                status_code=400,
                content={"detail": "Idempotency-Key is required for metered API requests"},
            )
            response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_requests)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
        elif (
            operation is not None
            and idempotency_key is not None
            and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", idempotency_key) is None
        ):
            response = JSONResponse(
                status_code=400,
                content={
                    "detail": (
                        "Idempotency-Key must be 1-128 characters using "
                        "letters, numbers, dot, underscore, colon, or hyphen"
                    )
                },
            )
            response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_requests)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
        else:
            request_fingerprint = None
            if operation is not None and meter is not None:
                request_fingerprint = hashlib.sha256(await request.body()).hexdigest()
            response = await call_next(request)
            # This is technical usage telemetry, not an entitlement or money charge.
            tenant_id = getattr(request.state, "tenant_id", None)
            api_key_id = getattr(request.state, "api_key_id", None)
            if operation and response.status_code < 400 and tenant_id and api_key_id and meter is not None:
                try:
                    event = meter.record(
                        tenant_id=tenant_id,
                        api_key_id=api_key_id,
                        request_id=request.state.request_id,
                        idempotency_key=idempotency_key or request.state.request_id,
                        operation=operation,
                        request_fingerprint=request_fingerprint,
                    )
                    response.headers["X-JAS-SI-Usage-Event-ID"] = event["event_id"]
                    if event.get("replayed"):
                        response.headers["X-JAS-SI-Usage-Replayed"] = "true"
                except Exception:
                    _log_security_event(
                        "usage_metering_failure", request,
                        reason_code="usage_event_not_persisted",
                    )
                    response = JSONResponse(
                        status_code=503,
                        content={
                            "detail": (
                                "Usage could not be durably recorded; "
                                "the request result is withheld"
                            )
                        },
                    )
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
    event_store: SecurityEventStore = Depends(get_security_event_store),
) -> None:
    """Use tenant-scoped registry keys in preview/production; static key only in dev/test."""
    _require_enabled(request)

    if settings.environment in {"preview", "production"}:
        if not x_api_key:
            _log_security_event(
                "authentication_failure",
                request,
                event_store,
                status_code=401,
                reason_code="missing_api_key",
            )
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        if not settings.database_url or not settings.api_key_pepper:
            _log_security_event(
                "configuration_error",
                request,
                event_store,
                status_code=503,
                reason_code="api_key_registry_not_configured",
            )
            raise HTTPException(
                status_code=503,
                detail="API key registry is not configured",
            )

        try:
            registry = PostgresApiKeyRegistry(
                settings.database_url,
                settings.api_key_pepper,
            )
            authenticated = registry.authenticate(x_api_key)
        except Exception:
            _log_security_event(
                "authentication_registry_error",
                request,
                event_store,
                status_code=503,
                reason_code="api_key_registry_unavailable",
            )
            raise HTTPException(
                status_code=503,
                detail="API key registry is temporarily unavailable",
            ) from None

        if authenticated is None:
            _log_security_event(
                "authentication_failure",
                request,
                event_store,
                status_code=401,
                reason_code="invalid_or_inactive_api_key",
            )
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        required_scopes = {
            "/v1/authorize": "authorization:check",
            "/v1/verify": "outcomes:submit",
            "/v1/github/evidence": "github:evidence:verify",
            "/v1/usage": "usage:read",
        }
        required_scope = required_scopes.get(request.url.path)
        if required_scope and required_scope not in authenticated.scopes:
            _log_security_event(
                "authorization_scope_denied",
                request,
                event_store,
                status_code=403,
                tenant_id=str(authenticated.tenant_id),
                key_id=str(authenticated.key_id),
                required_scope=required_scope,
            )
            raise HTTPException(
                status_code=403,
                detail="API key is not permitted to perform this operation",
            )

        request.state.tenant_id = str(authenticated.tenant_id)
        request.state.api_key_id = str(authenticated.key_id)
        request.state.api_key_scopes = sorted(authenticated.scopes)
        return

    configured_key = settings.api_key
    if not configured_key:
        _log_security_event(
            "configuration_error",
            request,
            event_store,
            status_code=503,
            reason_code="api_key_not_configured",
        )
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured",
        )

    if not x_api_key or not hmac.compare_digest(
        x_api_key.encode("utf-8"),
        configured_key.encode("utf-8"),
    ):
        _log_security_event(
            "authentication_failure",
            request,
            event_store,
            status_code=401,
            reason_code="invalid_api_key" if x_api_key else "missing_api_key",
        )
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def developer_console() -> HTMLResponse:
    """Serve the public JAS-SI developer landing page."""
    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/demo", response_class=HTMLResponse, include_in_schema=False)
def verification_demo() -> HTMLResponse:
    """Serve an explicitly synthetic, non-interactive-with-backend walkthrough."""
    return HTMLResponse(content=DEMO_HTML)


@app.get("/live-demo", response_class=HTMLResponse, include_in_schema=False)
def live_github_demo() -> HTMLResponse:
    """Serve a live, read-only GitHub evidence API console."""
    return HTMLResponse(content=LIVE_GITHUB_DEMO_HTML)


@app.get("/health")
def health() -> dict:
    """Public liveness endpoint; never return secret configuration."""
    return {
        "service": settings.service_name,
        "status": "ok",
        "api_enabled": settings.api_enabled,
    }


@app.get("/v1/usage", dependencies=[Depends(_require_api_key)])
def usage_summary(request: Request, since: Optional[datetime] = None) -> dict:
    """Return only the authenticated tenant technical usage totals."""
    tenant_id = getattr(request.state, "tenant_id", None)
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Tenant-scoped API key authentication is required")
    if not settings.database_url:
        raise HTTPException(status_code=503, detail="Usage storage is not configured")
    window_start = since or (datetime.now(timezone.utc) - timedelta(days=30))
    if window_start.tzinfo is None:
        raise HTTPException(status_code=422, detail="since must include a timezone")
    try:
        meter = getattr(request.app.state, "usage_meter", None)
        if meter is None:
            meter = PostgresUsageMeter(settings.database_url)
        return meter.summary(tenant_id=tenant_id, since=window_start)
    except Exception:
        raise HTTPException(status_code=503, detail="Tenant usage summary is temporarily unavailable") from None

@app.post(
    "/v1/authorize",
    dependencies=[Depends(_require_api_key)],
)
def authorize(
    payload: AuthorizeRequest,
    request: Request,
    event_store: SecurityEventStore = Depends(get_security_event_store),
) -> dict:
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
            event_store,
            status_code=503,
            reason_code="evaluation_unavailable",
        )
        raise HTTPException(
            status_code=503,
            detail="Authorization evaluation unavailable",
        ) from None

    persisted = _log_security_event(
        "authorization_evaluated",
        request,
        event_store,
        status_code=200,
        action_id=decision.action_id,
        allowed=bool(decision.allowed),
        reason_code="allowed" if decision.allowed else "denied",
    )

    if not persisted:
        raise HTTPException(
            status_code=503,
            detail="Authorization result could not be securely audited",
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
def verify(
    payload: VerifyRequest,
    request: Request,
    event_store: SecurityEventStore = Depends(get_security_event_store),
) -> dict:
    report = ActionReport(
        action_id=payload.action_id,
        claimed_success=payload.claimed_success,
    )

    evidence = None
    evidence_submitted = (
        payload.observed_state is not None
        or payload.evidence_ref is not None
    )

    if evidence_submitted:
        if not payload.observed_state or not payload.evidence_ref:
            _log_security_event(
                "verification_input_rejected",
                request,
                event_store,
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
            collected_independently=False,
        )

    try:
        result = _sdk.verify(report, evidence)
    except Exception:
        _log_security_event(
            "verification_error",
            request,
            event_store,
            status_code=503,
            reason_code="verification_unavailable",
        )
        raise HTTPException(
            status_code=503,
            detail="Outcome verification unavailable",
        ) from None

    status = getattr(result.status, "value", result.status)

    persisted = _log_security_event(
        "outcome_verified",
        request,
        event_store,
        status_code=200,
        action_id=result.action_id,
        verification_status=str(status)[:64],
    )

    if not persisted:
        raise HTTPException(
            status_code=503,
            detail="Verification result could not be securely audited",
        )

    return {
        "action_id": result.action_id,
        "status": status,
        "reason": result.reason,
        "evidence_origin": (
            "caller_submitted"
            if evidence_submitted
            else "not_provided"
        ),
    }


# Include GitHub Evidence Verification router with API key protection.
app.include_router(
    github_verify_router,
    dependencies=[Depends(_require_api_key)],
)
