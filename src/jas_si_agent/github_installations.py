"""Tenant-bound GitHub App installation credential contracts.

A host-provided adapter must prove that the GitHub App installation belongs
to the authenticated tenant and is installed on the requested repository.
This module validates that binding and token lifetime; it does not itself
implement OAuth, installation discovery, token minting, or secret storage.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID


_REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class GitHubCredentialResolutionError(RuntimeError):
    """A tenant GitHub credential could not be safely resolved."""


@dataclass(frozen=True)
class TenantGitHubInstallationCredential:
    tenant_id: UUID
    installation_id: int
    repository: str
    access_token: str = field(repr=False, compare=False)
    expires_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, UUID):
            raise ValueError("tenant_id must be a UUID")
        if (
            isinstance(self.installation_id, bool)
            or not isinstance(self.installation_id, int)
            or self.installation_id <= 0
        ):
            raise ValueError("installation_id must be a positive integer")
        if (
            not isinstance(self.repository, str)
            or not _REPOSITORY_PATTERN.fullmatch(self.repository)
        ):
            raise ValueError("repository must be an owner/name identifier")
        if (
            not isinstance(self.access_token, str)
            or not self.access_token
            or len(self.access_token) > 4096
            or self.access_token.strip() != self.access_token
            or any(ord(char) < 33 or ord(char) == 127 for char in self.access_token)
        ):
            raise ValueError("installation access token is invalid")
        if (
            not isinstance(self.expires_at, datetime)
            or self.expires_at.tzinfo is None
            or self.expires_at.utcoffset() is None
        ):
            raise ValueError("expires_at must be timezone-aware")


class TenantGitHubInstallationProvider(Protocol):
    """Trusted host adapter for tenant-owned GitHub App installations."""

    def resolve(
        self,
        *,
        tenant_id: UUID,
        repository: str,
    ) -> TenantGitHubInstallationCredential | None:
        """Return a short-lived token only for a tenant-installed repository."""


def resolve_tenant_github_credential(
    provider: TenantGitHubInstallationProvider,
    *,
    tenant_id: UUID,
    repository: str,
    now: datetime | None = None,
) -> TenantGitHubInstallationCredential | None:
    """Resolve and validate a credential against tenant, repository and expiry."""

    if not isinstance(tenant_id, UUID):
        raise GitHubCredentialResolutionError("Authenticated tenant identity is required")
    if not isinstance(repository, str) or not _REPOSITORY_PATTERN.fullmatch(repository):
        raise GitHubCredentialResolutionError("Repository identifier is invalid")
    try:
        credential = provider.resolve(tenant_id=tenant_id, repository=repository)
    except Exception:
        # Do not propagate provider exceptions: they may contain secrets.
        raise GitHubCredentialResolutionError(
            "Tenant GitHub connection is unavailable"
        ) from None
    if credential is None:
        return None
    if not isinstance(credential, TenantGitHubInstallationCredential):
        raise GitHubCredentialResolutionError(
            "Tenant GitHub provider returned an invalid credential"
        )
    if credential.tenant_id != tenant_id:
        raise GitHubCredentialResolutionError("GitHub installation tenant binding mismatch")
    if credential.repository.casefold() != repository.casefold():
        raise GitHubCredentialResolutionError(
            "GitHub installation repository binding mismatch"
        )
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    if credential.expires_at <= current_time:
        raise GitHubCredentialResolutionError("GitHub installation credential is expired")
    return credential
