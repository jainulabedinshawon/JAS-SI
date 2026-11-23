"""Isolated mTLS-only ASGI application for task-scoped GitHub capabilities.

This module intentionally does not import the public API application. Deploy it
as a separate ASGI process behind a trusted TLS listener that validates client
certificate chains and attaches the peer leaf DER to ASGI scope extensions.
"""
from __future__ import annotations

import uuid
from typing import Callable, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from jas_si_agent.config import Settings
from jas_si_agent.github_capability_asgi_tls import ASGITLSClientCertificateMiddleware
from jas_si_agent.github_capability_identity import (
    CertificateWorkloadIdentityRegistry,
    WorkloadIdentity,
    require_authenticated_workload,
)
from jas_si_agent.github_capability_broker import (
    GitHubCapabilityBrokerError,
    PostgresGitHubCapabilityBroker,
)


settings = Settings.from_env()


class GitHubCapabilityResolveRequest(BaseModel):
    """Only task selector and role-specific persisted lease proof are accepted."""

    model_config = ConfigDict(extra="forbid")

    task_id: uuid.UUID
    lease_fence: Optional[int] = Field(default=None, ge=1, strict=True)
    verifier_claim_token: Optional[uuid.UUID] = None


class GitHubCapabilityReadRequest(GitHubCapabilityResolveRequest):
    """A read request contains selectors only; persisted capability is authority."""

    repository: str = Field(min_length=3, max_length=200)
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    path: str = Field(min_length=1, max_length=500)


def require_enabled_authenticated_workload(request: Request) -> WorkloadIdentity:
    """Apply the isolated app kill-switch before evaluating certificate identity."""
    active_settings = request.app.state.github_capability_settings
    if (
        not active_settings.github_capability_broker_enabled
        or str(active_settings.environment).casefold() != "preview"
    ):
        raise HTTPException(status_code=404, detail="Not found")
    return require_authenticated_workload(request)


def create_github_capability_app(
    active_settings: Optional[Settings] = None,
    broker_factory: Optional[Callable[[str], object]] = None,
    read_proxy_factory: Optional[Callable[[Settings], object]] = None,
) -> FastAPI:
    """Build a Broker-only app with isolated state and no public API imports."""
    configured = active_settings or settings
    application = FastAPI(
        title="JAS-SI GitHub Capability Broker",
        version="0.1.0",
        description="Private mTLS workload capability resolution only.",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.add_middleware(ASGITLSClientCertificateMiddleware)
    application.state.github_capability_settings = configured
    application.state.github_capability_broker_factory = (
        broker_factory or PostgresGitHubCapabilityBroker
    )
    application.state.github_capability_read_proxy_factory = read_proxy_factory
    if isinstance(
        configured.github_capability_workload_identities,
        CertificateWorkloadIdentityRegistry,
    ):
        application.state.github_capability_identity_registry = (
            configured.github_capability_workload_identities
        )

    @application.post("/internal/github/capabilities/resolve")
    def resolve_github_task_capability(
        payload: GitHubCapabilityResolveRequest,
        request: Request,
        workload: WorkloadIdentity = Depends(
            require_enabled_authenticated_workload
        ),
    ) -> dict:
        """Resolve only a task-bound capability using TLS identity and DB proof."""
        database_url = configured.github_capability_broker_database_url
        if not database_url:
            raise HTTPException(
                status_code=503,
                detail="GitHub capability Broker database is not configured",
            )
        if workload.role == "worker":
            if payload.lease_fence is None or payload.verifier_claim_token is not None:
                raise HTTPException(status_code=422, detail="Worker lease fence is required")
        elif workload.role == "verifier":
            if payload.verifier_claim_token is None or payload.lease_fence is not None:
                raise HTTPException(status_code=422, detail="Verifier claim token is required")
        else:
            raise HTTPException(status_code=403, detail="Workload role is not authorized")

        broker = getattr(request.app.state, "github_capability_broker", None)
        if broker is None:
            try:
                broker = request.app.state.github_capability_broker_factory(database_url)
                request.app.state.github_capability_broker = broker
            except (TypeError, ValueError):
                raise HTTPException(
                    status_code=503,
                    detail="GitHub capability Broker is not configured safely",
                ) from None
        try:
            capability = broker.resolve(
                task_id=payload.task_id,
                principal_id=workload.principal_id,
                role=workload.role,
                lease_fence=payload.lease_fence,
                verifier_claim_token=payload.verifier_claim_token,
            )
        except GitHubCapabilityBrokerError:
            raise HTTPException(
                status_code=503,
                detail="GitHub capability authorization is unavailable",
            ) from None
        if capability is None:
            raise HTTPException(status_code=404, detail="Task capability is not authorized")

        return {
            "task_id": str(capability.task_id),
            "tenant_id": str(capability.tenant_id),
            "installation_id": capability.installation_id,
            "repository": capability.repository_full_name,
            "capability_role": capability.capability_role,
            "expires_at": capability.expires_at.isoformat(),
            "commit_sha": capability.commit_sha,
            "repository_paths": capability.repository_paths,
        }

    @application.post("/internal/github/capabilities/read")
    def read_github_task_file(
        payload: GitHubCapabilityReadRequest,
        request: Request,
        workload: WorkloadIdentity = Depends(
            require_enabled_authenticated_workload
        ),
    ) -> dict:
        """Resolve live task authority then perform a Broker-owned content read."""
        database_url = configured.github_capability_broker_database_url
        if not database_url:
            raise HTTPException(status_code=503, detail="GitHub capability Broker is not configured")
        if workload.role == "worker":
            if payload.lease_fence is None or payload.verifier_claim_token is not None:
                raise HTTPException(status_code=422, detail="Worker lease fence is required")
        elif workload.role == "verifier":
            if payload.verifier_claim_token is None or payload.lease_fence is not None:
                raise HTTPException(status_code=422, detail="Verifier claim token is required")
        else:
            raise HTTPException(status_code=403, detail="Workload role is not authorized")

        proxy_factory = request.app.state.github_capability_read_proxy_factory
        if proxy_factory is None:
            raise HTTPException(status_code=503, detail="Broker GitHub read proxy is not configured")
        broker = getattr(request.app.state, "github_capability_broker", None)
        if broker is None:
            try:
                broker = request.app.state.github_capability_broker_factory(database_url)
                request.app.state.github_capability_broker = broker
            except (TypeError, ValueError):
                raise HTTPException(status_code=503, detail="GitHub capability Broker is not configured safely") from None
        try:
            capability = broker.resolve(
                task_id=payload.task_id,
                principal_id=workload.principal_id,
                role=workload.role,
                lease_fence=payload.lease_fence,
                verifier_claim_token=payload.verifier_claim_token,
            )
            if capability is None:
                raise HTTPException(status_code=404, detail="Task capability is not authorized")
            proxy = request.app.state.github_capability_read_proxy
            if proxy is None:
                proxy = proxy_factory(configured)
                request.app.state.github_capability_read_proxy = proxy
            return proxy.read_file(
                capability=capability,
                repository=payload.repository,
                commit_sha=payload.commit_sha,
                path=payload.path,
            )
        except HTTPException:
            raise
        except GitHubCapabilityBrokerError:
            raise HTTPException(status_code=403, detail="GitHub repository read is not authorized") from None
        except Exception:
            # Do not leak token, HTTP headers, DSNs, or private key diagnostics.
            raise HTTPException(status_code=503, detail="GitHub repository read is unavailable") from None

    return application


# ASGI entry point: deploy separately from jas_si_agent.api:app.
app = create_github_capability_app()
