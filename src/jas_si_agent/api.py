"""JAS-SI REST API with authentication, rate limiting, and security logging.

The API evaluates authorization and verifies reported outcomes.
It does not execute actions.

The security event store is injected through FastAPI application state.
Critical operation results are withheld when their audit event cannot
be persisted. Authentication denials remain denials even if logging fails.

General API and customer email abuse limits use separate PostgreSQL-backed shared stores in deployed environments.
"""

from __future__ import annotations

import hashlib
import ipaddress
import hmac
import json
import logging
import re
import secrets
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
    Response,
    Cookie,
    Header,
    Security,
)
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from jas_si_agent.config import Settings
from jas_si_agent.api_rate_limit import PostgresApiRateLimiter
from jas_si_agent.customer_rate_limit import PostgresCustomerRateLimiter
from jas_si_agent.customer_identity import (
    CustomerIdentityConflict,
    CustomerIdentityError,
    PostgresCustomerIdentityStore,
    normalize_email,
    normalize_organization_name,
)
from jas_si_agent.customer_email import (
    CustomerEmailDeliveryError,
    SmtpCustomerEmailSender,
)
from jas_si_agent.customer_portal import CUSTOMER_PORTAL_HTML
from jas_si_agent.dashboard import DASHBOARD_HTML
from jas_si_agent.demo import DEMO_HTML
from jas_si_agent.live_demo import LIVE_GITHUB_DEMO_HTML
from jas_si_agent.api_key_registry import (
    ALLOWED_SCOPES,
    ApiKeyError,
    PostgresApiKeyRegistry,
)
from jas_si_agent.usage_meter import PostgresUsageMeter, UsageQuotaExceeded
from jas_si_agent.billing_catalog import get_free_monthly_units, get_plan_catalog
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
        "Versioned API routes have a shared sliding-window rate limit."
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
    if not settings.api_rate_limit_pepper:
        raise RuntimeError("Preview/production requires JAS_SI_API_RATE_LIMIT_PEPPER")

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
        if not registry.verify_api_key_auth_boundary():
            raise RuntimeError("API key authentication security boundary is not ready")
    except Exception as exc:
        raise RuntimeError(
            "API key registry readiness check failed; startup denied"
        ) from exc

    # Metering is prepared without running a migration at startup. All API-key
    # usage routines must already exist and pass their independent readiness gate.
    try:
        usage_meter = PostgresUsageMeter(settings.database_url)
        if not usage_meter.verify_api_key_usage_routines():
            raise RuntimeError("API-key usage database routines are not ready")
    except Exception as exc:
        raise RuntimeError(
            "API-key usage readiness check failed; startup denied"
        ) from exc
    try:
        api_rate_limiter = PostgresApiRateLimiter(
            settings.database_url,
            settings.api_rate_limit_pepper,
        )
        if not api_rate_limiter.verify_schema():
            raise RuntimeError("Shared API rate-limit database boundary is not ready")
    except Exception as exc:
        raise RuntimeError(
            "Shared API rate-limit readiness check failed; startup denied"
        ) from exc

    app.state.security_event_store = store
    app.state.usage_meter = usage_meter
    app.state.api_rate_limiter = api_rate_limiter

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

# Customer email rate limits are stored in PostgreSQL so limits are shared
# across serverless instances. Raw client IP addresses are never persisted.
_CUSTOMER_EMAIL_LIMIT = 5
_CUSTOMER_EMAIL_WINDOW_SECONDS = 15 * 60


def _get_customer_rate_limiter(request: Request) -> PostgresCustomerRateLimiter:
    limiter = getattr(request.app.state, "customer_rate_limiter", None)
    if limiter is not None:
        return limiter
    if not settings.customer_database_url or not settings.customer_token_pepper:
        raise HTTPException(
            status_code=503,
            detail="Customer abuse protection is not configured",
        )
    try:
        limiter = PostgresCustomerRateLimiter(
            settings.customer_database_url,
            settings.customer_token_pepper,
        )
        if not limiter.verify_schema():
            raise RuntimeError("Customer rate-limit schema is not installed")
        request.app.state.customer_rate_limiter = limiter
        return limiter
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Customer abuse protection is temporarily unavailable",
        ) from None


def _get_api_rate_limiter(request: Request):
    limiter = getattr(request.app.state, "api_rate_limiter", None)
    if limiter is not None:
        return limiter
    if settings.database_url and settings.api_rate_limit_pepper:
        try:
            limiter = PostgresApiRateLimiter(
                settings.database_url, settings.api_rate_limit_pepper
            )
            if not limiter.verify_schema():
                raise RuntimeError("Shared API rate-limit schema is not ready")
            request.app.state.api_rate_limiter = limiter
            return limiter
        except Exception:
            raise HTTPException(
                status_code=503,
                detail="Shared API rate limiting is temporarily unavailable",
            ) from None
    if settings.environment in {"preview", "production"}:
        raise HTTPException(
            status_code=503,
            detail="Shared API rate limiting is not configured",
        )
    return None


def _api_client_ip(request: Request) -> str:
    # Vercel overwrites these edge-provided headers. Never trust a client-
    # supplied X-Forwarded-For chain in deployed environments.
    forwarded = request.headers.get("x-vercel-forwarded-for")
    if not forwarded:
        forwarded = request.headers.get("x-forwarded-for")
    candidate = forwarded.split(",", 1)[0].strip() if forwarded else ""
    if not candidate:
        if settings.environment in {"preview", "production"}:
            raise HTTPException(
                status_code=503,
                detail="Trusted API client address is unavailable",
            )
        if request.client is not None:
            candidate = request.client.host
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        # Starlette's TestClient uses the non-IP peer name "testclient".
        # Normalize that test-only transport identity to loopback.
        if settings.environment == "test" and candidate == "testclient":
            return "127.0.0.1"
        raise HTTPException(
            status_code=503,
            detail="API client address could not be verified",
        ) from None


def _customer_client_ip(request: Request) -> str:
    # Prefer Vercel's preserved client address. Fall back only to the
    # x-forwarded-for header overwritten by Vercel's trusted edge.
    # Never trust request.client in preview/production: it may be an
    # internal runtime peer rather than the public caller.
    forwarded = request.headers.get("x-vercel-forwarded-for")
    if not forwarded:
        forwarded = request.headers.get("x-forwarded-for")
    candidate = forwarded.split(",", 1)[0].strip() if forwarded else ""
    if not candidate:
        if settings.environment in {"preview", "production"}:
            raise HTTPException(
                status_code=503,
                detail="Trusted customer client address is unavailable",
            )
        if request.client is not None:
            candidate = request.client.host
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        raise HTTPException(
            status_code=503,
            detail="Customer client address could not be verified",
        ) from None

def _enforce_customer_email_rate_limit(request: Request) -> None:
    limiter = _get_customer_rate_limiter(request)
    try:
        allowed, retry_after = limiter.check(
            _customer_client_ip(request),
            limit=_CUSTOMER_EMAIL_LIMIT,
            window_seconds=_CUSTOMER_EMAIL_WINDOW_SECONDS,
        )
    except Exception:
        # Fail closed: an unavailable shared limiter must not silently
        # downgrade public email endpoints to process-local protection.
        raise HTTPException(
            status_code=503,
            detail="Customer abuse protection is temporarily unavailable",
        ) from None
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many customer email requests. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

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

    # Apply a shared ingress limit to every versioned API route. Customer
    # email endpoints additionally retain their stricter, separate abuse limiter.
    if request.url.path.startswith("/v1/"):
        response = None
        try:
            client_ip = _api_client_ip(request)
            shared_limiter = _get_api_rate_limiter(request)
            if shared_limiter is None:
                allowed, remaining, retry_after = _rate_limit_decision(client_ip)
            else:
                allowed, remaining, retry_after = shared_limiter.check(
                    client_ip,
                    limit=settings.rate_limit_requests,
                    window_seconds=settings.rate_limit_window_seconds,
                )
        except HTTPException as exc:
            response = JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=exc.headers,
            )
            shared_limiter = None
            allowed, remaining, retry_after = False, 0, 0
        except Exception:
            # Never silently downgrade a configured/deployed shared limiter.
            response = JSONResponse(
                status_code=503,
                content={"detail": "Shared API rate limiting is temporarily unavailable"},
            )
            shared_limiter = None
            allowed, remaining, retry_after = False, 0, 0
        idempotency_key = request.headers.get("Idempotency-Key")
        metered_paths = {
            "/v1/authorize": "authorization.evaluate",
            "/v1/verify": "outcome.submit",
            "/v1/github/evidence": "github.evidence.verify",
        }
        operation = metered_paths.get(request.url.path)
        meter = getattr(request.app.state, "usage_meter", None)

        if response is not None and response.status_code == 503:
            pass
        elif not allowed:
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
            if operation is not None:
                request_body = await request.body()
                request.state.request_fingerprint = hashlib.sha256(request_body).hexdigest()

                # Replay the body for FastAPI after calculating its digest.
                body_sent = False

                async def receive_body():
                    nonlocal body_sent
                    if body_sent:
                        return {"type": "http.request", "body": b"", "more_body": False}
                    body_sent = True
                    return {"type": "http.request", "body": request_body, "more_body": False}

                request._receive = receive_body
            response = await call_next(request)
            event = getattr(request.state, "usage_event", None)
            if event is not None:
                response.headers["X-JAS-SI-Usage-Event-ID"] = event["event_id"]
                response.headers["X-JAS-SI-Quota-Limit"] = str(event["monthly_limit"])
                response.headers["X-JAS-SI-Quota-Used"] = str(event["used_units"])
                response.headers["X-JAS-SI-Quota-Remaining"] = str(event["remaining_units"])
                response.headers["X-JAS-SI-Quota-Resets-At"] = event["resets_at"]
                if event.get("replayed"):
                    response.headers["X-JAS-SI-Usage-Replayed"] = "true"
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


def _record_usage_for_authenticated_tenant(request: Request) -> None:
    """Atomically reserve one monthly Free-plan unit before executing the API handler."""
    operations = {
        "/v1/authorize": "authorization.evaluate",
        "/v1/verify": "outcome.submit",
        "/v1/github/evidence": "github.evidence.verify",
    }
    operation = operations.get(request.url.path)
    tenant_id = getattr(request.state, "tenant_id", None)
    api_key_id = getattr(request.state, "api_key_id", None)
    if operation is None or not tenant_id or not api_key_id:
        return
    candidate_digest = getattr(request.state, "api_key_candidate_digest", None)
    required_scope = {
        "authorization.evaluate": "authorization:check",
        "outcome.submit": "outcomes:submit",
        "github.evidence.verify": "github:evidence:verify",
    }[operation]
    meter = getattr(request.app.state, "usage_meter", None)
    fingerprint = getattr(request.state, "request_fingerprint", None)
    if meter is None or fingerprint is None:
        _log_security_event("usage_quota_unavailable", request, reason_code="durable_quota_meter_not_ready")
        raise HTTPException(status_code=503, detail="Usage quota service is not ready; request denied")
    try:
        request.state.usage_event = meter.record_authenticated(
            api_key_id=api_key_id,
            candidate_digest=candidate_digest,
            required_scope=required_scope,
            request_id=request.state.request_id,
            idempotency_key=request.headers.get("Idempotency-Key") or request.state.request_id,
            operation=operation,
            request_fingerprint=fingerprint,
            monthly_limit=get_free_monthly_units(),
        )
    except UsageQuotaExceeded as exc:
        retry_after = max(1, int((exc.resets_at - datetime.now(timezone.utc)).total_seconds() + 0.999))
        _log_security_event(
            "usage_quota_exceeded", request, reason_code="free_monthly_quota_exhausted",
            monthly_limit=exc.monthly_limit, used_units=exc.used_units,
        )
        raise HTTPException(
            status_code=429,
            detail={
                "code": "monthly_quota_exceeded",
                "message": "The Free monthly API quota has been exhausted",
                "monthly_limit": exc.monthly_limit,
                "used_units": exc.used_units,
                "resets_at": exc.resets_at.isoformat(),
            },
            headers={
                "Retry-After": str(retry_after),
                "X-JAS-SI-Quota-Limit": str(exc.monthly_limit),
                "X-JAS-SI-Quota-Used": str(exc.used_units),
                "X-JAS-SI-Quota-Remaining": "0",
                "X-JAS-SI-Quota-Resets-At": exc.resets_at.isoformat(),
            },
        ) from None
    except Exception:
        _log_security_event("usage_metering_failure", request, reason_code="usage_event_not_persisted")
        raise HTTPException(status_code=503, detail="Usage quota could not be durably recorded; request denied") from None


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
            "/v1/usage/events": "usage:read",
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
        # Keep only the peppered digest in this request context; never retain the raw token.
        request.state.api_key_candidate_digest = authenticated.candidate_digest
        request.state.api_key_required_scope = required_scope
        _record_usage_for_authenticated_tenant(request)
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



class CustomerRegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    organization_name: str = Field(min_length=1, max_length=160)


class CustomerEmailRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class CustomerTokenRequest(BaseModel):
    token: str = Field(min_length=32, max_length=128)


class CustomerApiKeyCreateRequest(BaseModel):
    key_name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(min_length=1, max_length=4)
    expires_in_days: int = Field(default=90, ge=1, le=365)


def _get_customer_identity_store(request: Request) -> PostgresCustomerIdentityStore:
    store = getattr(request.app.state, "customer_identity_store", None)
    if store is not None:
        return store
    if not settings.customer_database_url or not settings.customer_token_pepper:
        raise HTTPException(
            status_code=503,
            detail="Customer identity is not configured",
        )
    try:
        store = PostgresCustomerIdentityStore(
            settings.customer_database_url,
            settings.customer_token_pepper,
        )
        if not store.verify_schema():
            raise RuntimeError("Customer identity schema is not installed")
        if not store.verify_security_boundary():
            raise RuntimeError("Customer identity database privileges are not isolated")
        request.app.state.customer_identity_store = store
        return store
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Customer identity service is temporarily unavailable",
        ) from None



def _get_customer_usage_identity_store(request: Request) -> PostgresCustomerIdentityStore:
    store = _get_customer_identity_store(request)
    # Bind the cached verification to the exact store instance. A process-wide
    # boolean can outlive a DSN/store change and must never authorize a new store.
    if getattr(request.app.state, "customer_usage_read_boundary_store", None) is store:
        return store
    try:
        if store.verify_usage_read_boundary() is not True:
            raise RuntimeError("Customer usage database boundary is not installed")
        request.app.state.customer_usage_read_boundary_store = store
        return store
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Customer usage service is temporarily unavailable",
        ) from None

def _get_customer_api_key_registry() -> PostgresApiKeyRegistry:
    if not settings.customer_api_key_database_url or not settings.api_key_pepper or not settings.customer_token_pepper:
        raise HTTPException(
            status_code=503,
            detail="Customer API key management is not configured",
        )
    try:
        registry = PostgresApiKeyRegistry(
            settings.customer_api_key_database_url,
            settings.api_key_pepper,
            customer_session_pepper=settings.customer_token_pepper,
        )
        return registry
    except ApiKeyError:
        raise HTTPException(
            status_code=503,
            detail="Customer API key management is unavailable",
        ) from None
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Customer API key management is temporarily unavailable",
        ) from None


def _require_customer_session(request: Request):
    session_token = request.cookies.get("jassi_customer_session")
    if not session_token:
        raise HTTPException(status_code=401, detail="Customer session is required")
    store = _get_customer_identity_store(request)
    try:
        account = store.authenticate_session(session_token)
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Customer session service is unavailable",
        ) from None
    if account is None:
        raise HTTPException(status_code=401, detail="Customer session is invalid or expired")
    if account.status != "active":
        raise HTTPException(status_code=403, detail="Customer account is not active")
    request.state.tenant_id = str(account.tenant_id)
    request.state.customer_account_id = str(account.account_id)
    return account


def _require_customer_csrf(request: Request) -> None:
    cookie = request.cookies.get("jassi_customer_csrf")
    header = request.headers.get("X-JAS-SI-CSRF")
    if not cookie or not header or not hmac.compare_digest(cookie, header):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def _get_customer_email_sender() -> SmtpCustomerEmailSender:
    if not settings.customer_smtp_host or not settings.customer_smtp_sender:
        raise HTTPException(
            status_code=503,
            detail="Customer email delivery is not configured",
        )
    try:
        return SmtpCustomerEmailSender(
            host=settings.customer_smtp_host,
            port=settings.customer_smtp_port,
            username=settings.customer_smtp_username,
            password=settings.customer_smtp_password,
            sender=settings.customer_smtp_sender,
            public_base_url=settings.customer_public_base_url,
        )
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Customer email delivery is not configured correctly",
        ) from None


def _customer_account_response(account) -> dict:
    return {
        "account_id": str(account.account_id),
        "email": account.email,
        "organization_name": account.organization_name,
        "status": account.status,
    }


def _send_customer_link_safely(
    request: Request,
    sender: SmtpCustomerEmailSender,
    link,
) -> None:
    try:
        sender.send_link(
            recipient=link.email,
            purpose=link.purpose,
            token=link.token,
            expires_at=link.expires_at,
        )
    except CustomerEmailDeliveryError:
        # Never log the email address or one-time token, and never expose
        # account-existence or mail-provider status to the public caller.
        _log_security_event(
            "customer_email_delivery_failed",
            request,
            reason_code="smtp_delivery_failed",
        )


@app.get("/customer", response_class=HTMLResponse, include_in_schema=False)
def customer_portal() -> HTMLResponse:
    """Serve the standalone JAS-SI customer sign-up and sign-in portal."""
    return HTMLResponse(content=CUSTOMER_PORTAL_HTML)


@app.post("/v1/customer/register", status_code=202)
def customer_register(
    payload: CustomerRegisterRequest,
    request: Request,
) -> dict:
    _enforce_customer_email_rate_limit(request)
    try:
        email = normalize_email(payload.email)
        organization = normalize_organization_name(payload.organization_name)
    except CustomerIdentityError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    store = _get_customer_identity_store(request)
    sender = _get_customer_email_sender()
    try:
        try:
            link = store.register(email, organization)
        except CustomerIdentityConflict:
            # Resend only for a pending account; active accounts remain
            # indistinguishable from unknown accounts to prevent enumeration.
            link = store.issue_verification_link(email)
    except CustomerIdentityError:
        raise HTTPException(
            status_code=503,
            detail="Customer registration is temporarily unavailable",
        ) from None
    if link is not None:
        _send_customer_link_safely(request, sender, link)
    return {
        "message": "If the address is eligible, a verification link has been sent."
    }


@app.post("/v1/customer/login", status_code=202)
def customer_login(
    payload: CustomerEmailRequest,
    request: Request,
) -> dict:
    _enforce_customer_email_rate_limit(request)
    try:
        email = normalize_email(payload.email)
    except CustomerIdentityError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    store = _get_customer_identity_store(request)
    sender = _get_customer_email_sender()
    try:
        link = store.issue_login_link(email)
    except CustomerIdentityError:
        raise HTTPException(
            status_code=503,
            detail="Customer sign-in is temporarily unavailable",
        ) from None
    if link is not None:
        _send_customer_link_safely(request, sender, link)
    return {
        "message": "If an active account exists, a sign-in link has been sent."
    }


@app.post("/v1/customer/verify-email")
def customer_verify_email(
    payload: CustomerTokenRequest,
    request: Request,
) -> dict:
    store = _get_customer_identity_store(request)
    try:
        account = store.verify_email(payload.token)
    except CustomerIdentityError:
        raise HTTPException(
            status_code=400,
            detail="The verification link is invalid or expired",
        ) from None
    _log_security_event(
        "customer_email_verified",
        request,
        tenant_id=str(account.tenant_id),
        account_id=str(account.account_id),
    )
    return {"verified": True, "message": "Email address verified. You may now sign in."}


@app.post("/v1/customer/session")
def customer_create_session(
    payload: CustomerTokenRequest,
    request: Request,
    response: Response,
) -> dict:
    store = _get_customer_identity_store(request)
    try:
        session = store.consume_login_link(payload.token)
    except CustomerIdentityError:
        raise HTTPException(
            status_code=400,
            detail="The sign-in link is invalid or expired",
        ) from None
    secure = settings.environment in {"preview", "production"}
    max_age = max(1, int((session.expires_at - datetime.now(timezone.utc)).total_seconds()))
    csrf_token = secrets.token_urlsafe(24)
    response.set_cookie(
        "jassi_customer_session",
        session.token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        "jassi_customer_csrf",
        csrf_token,
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )
    _log_security_event(
        "customer_session_created",
        request,
        tenant_id=str(session.account.tenant_id),
        account_id=str(session.account.account_id),
    )
    return _customer_account_response(session.account)


@app.get("/v1/customer/me")
def customer_me(
    request: Request,
    session_token: Optional[str] = Cookie(default=None, alias="jassi_customer_session"),
) -> dict:
    if not session_token:
        raise HTTPException(status_code=401, detail="Customer session is required")
    store = _get_customer_identity_store(request)
    try:
        account = store.authenticate_session(session_token)
    except Exception:
        raise HTTPException(status_code=503, detail="Customer session service is unavailable") from None
    if account is None:
        raise HTTPException(status_code=401, detail="Customer session is invalid or expired")
    return _customer_account_response(account)


@app.post("/v1/customer/logout")
def customer_logout(
    request: Request,
    response: Response,
    session_token: Optional[str] = Cookie(default=None, alias="jassi_customer_session"),
    csrf_cookie: Optional[str] = Cookie(default=None, alias="jassi_customer_csrf"),
    csrf_header: Optional[str] = Header(default=None, alias="X-JAS-SI-CSRF"),
) -> dict:
    if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    if session_token:
        store = _get_customer_identity_store(request)
        try:
            store.revoke_session(session_token)
        except Exception:
            raise HTTPException(status_code=503, detail="Customer sign-out is unavailable") from None
    response.delete_cookie("jassi_customer_session", path="/", httponly=True, samesite="strict")
    response.delete_cookie("jassi_customer_csrf", path="/", samesite="strict")
    return {"signed_out": True}


@app.get("/v1/customer/usage")
def customer_usage_summary(request: Request) -> dict:
    """Return technical usage through a database routine bound to the live session."""
    _require_customer_session(request)
    session_token = request.cookies.get("jassi_customer_session") or ""
    store = _get_customer_usage_identity_store(request)
    try:
        since = datetime.now(timezone.utc) - timedelta(days=30)
        result = store.usage_summary(session_token, since)
        used = int(result.pop("current_month_units"))
        now = datetime.now(timezone.utc)
        period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if period_start.month == 12:
            period_end = period_start.replace(year=period_start.year + 1, month=1)
        else:
            period_end = period_start.replace(month=period_start.month + 1)
        monthly_limit = get_free_monthly_units()
        result["quota"] = {
            "period": "utc_calendar_month",
            "period_start": period_start.isoformat(),
            "resets_at": period_end.isoformat(),
            "monthly_limit": monthly_limit,
            "used_units": used,
            "remaining_units": max(0, monthly_limit - used),
            "exhausted": used >= monthly_limit,
        }
        return result
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Customer usage summary is temporarily unavailable",
        ) from None


@app.get("/v1/customer/usage/events")
def customer_usage_events(
    request: Request,
    limit: int = 50,
    before: Optional[datetime] = None,
    before_event_id: Optional[uuid.UUID] = None,
) -> dict:
    """Return a keyset page using tenant identity resolved inside PostgreSQL."""
    _require_customer_session(request)
    session_token = request.cookies.get("jassi_customer_session") or ""
    store = _get_customer_usage_identity_store(request)
    try:
        return store.usage_events(
            session_token, limit=limit, before=before,
            before_event_id=str(before_event_id) if before_event_id else None,
        )
    except CustomerIdentityError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except Exception:
        raise HTTPException(status_code=503, detail="Customer usage history is temporarily unavailable") from None


@app.get("/v1/customer/api-keys")
def customer_list_api_keys(request: Request) -> dict:
    _require_customer_session(request)
    session_token = request.cookies.get("jassi_customer_session") or ""
    registry = _get_customer_api_key_registry()
    try:
        keys = registry.customer_list_keys(session_token)
    except ApiKeyError:
        raise HTTPException(status_code=503, detail="Customer API keys are temporarily unavailable") from None
    return {"items": keys, "count": len(keys)}


@app.post("/v1/customer/api-keys", status_code=201)
def customer_create_api_key(payload: CustomerApiKeyCreateRequest, request: Request, response: Response) -> dict:
    _require_customer_session(request)
    _require_customer_csrf(request)
    session_token = request.cookies.get("jassi_customer_session") or ""
    name = payload.key_name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Key name is required")
    scopes = frozenset(payload.scopes)
    if not scopes or not scopes.issubset(ALLOWED_SCOPES):
        raise HTTPException(status_code=422, detail="One or more API key scopes are invalid")
    registry = _get_customer_api_key_registry()
    expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)
    try:
        issued = registry.customer_issue_key(session_token, name, scopes, expires_at)
    except ApiKeyError:
        raise HTTPException(status_code=503, detail="Customer API key could not be created") from None
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return {
        "key_id": str(issued.key_id), "key_name": name, "key_prefix": issued.prefix,
        "token": issued.token, "scopes": sorted(scopes),
        "expires_at": issued.expires_at.isoformat() if issued.expires_at else None,
        "warning": "Copy this API key now. It will not be shown again.",
    }


@app.post("/v1/customer/api-keys/{key_id}/revoke")
def customer_revoke_api_key(key_id: str, request: Request) -> dict:
    _require_customer_session(request)
    _require_customer_csrf(request)
    session_token = request.cookies.get("jassi_customer_session") or ""
    try:
        parsed_key_id = uuid.UUID(key_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=404, detail="API key not found") from None
    registry = _get_customer_api_key_registry()
    try:
        revoked = registry.customer_revoke_key(session_token, parsed_key_id)
    except ApiKeyError:
        raise HTTPException(status_code=503, detail="Customer API key revocation is temporarily unavailable") from None
    if not revoked:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"revoked": True, "key_id": str(parsed_key_id)}


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


@app.get("/plans")
def public_plan_catalog() -> dict:
    """Expose public plan metadata without enabling paid checkout."""
    return get_plan_catalog()


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
        candidate_digest = getattr(request.state, "api_key_candidate_digest", None)
        api_key_id = getattr(request.state, "api_key_id", None)
        if not api_key_id or not isinstance(candidate_digest, bytes) or len(candidate_digest) != 32:
            raise RuntimeError("Authenticated API-key proof is unavailable")
        result = meter.summary_authenticated(
            api_key_id=api_key_id, candidate_digest=candidate_digest,
            since=window_start, tenant_id_for_response=tenant_id,
        )
        result["quota"] = meter.quota_status_authenticated(
            api_key_id=api_key_id, candidate_digest=candidate_digest,
            monthly_limit=get_free_monthly_units(),
        )
        return result
    except Exception:
        raise HTTPException(status_code=503, detail="Tenant usage summary is temporarily unavailable") from None

@app.get("/v1/usage/events", dependencies=[Depends(_require_api_key)])
def usage_events(
    request: Request,
    limit: int = 50,
    before: Optional[datetime] = None,
    before_event_id: Optional[str] = None,
) -> dict:
    """Return a bounded, keyset-paginated history for the authenticated API key."""
    if not settings.database_url:
        raise HTTPException(status_code=503, detail="Usage storage is not configured")
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 100")
    if (before is None) != (before_event_id is None):
        raise HTTPException(status_code=422, detail="before and before_event_id must be provided together")
    if before_event_id is not None:
        try:
            uuid.UUID(before_event_id)
        except (TypeError, ValueError):
            raise HTTPException(status_code=422, detail="before_event_id must be a UUID") from None
    if before is not None and before.tzinfo is None:
        raise HTTPException(status_code=422, detail="before must include a timezone")
    api_key_id = getattr(request.state, "api_key_id", None)
    candidate_digest = getattr(request.state, "api_key_candidate_digest", None)
    if not api_key_id or not isinstance(candidate_digest, bytes) or len(candidate_digest) != 32:
        raise HTTPException(status_code=403, detail="Authenticated API-key proof is unavailable")
    try:
        meter = getattr(request.app.state, "usage_meter", None)
        if meter is None:
            meter = PostgresUsageMeter(settings.database_url)
        return meter.events_authenticated(
            api_key_id=api_key_id,
            candidate_digest=candidate_digest,
            limit=limit,
            before=before,
            before_event_id=before_event_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except Exception:
        raise HTTPException(status_code=503, detail="Tenant usage history is temporarily unavailable") from None


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
