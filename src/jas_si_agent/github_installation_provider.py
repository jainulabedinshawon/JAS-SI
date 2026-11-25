"""PostgreSQL-backed tenant GitHub installation credential provider.

This adapter resolves only active, verified tenant/repository bindings through
the database-owned SECURITY DEFINER routine. It never accepts an installation
ID from a task payload and never persists installation access tokens.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import timezone
from typing import Any
from uuid import UUID

from jas_si_agent.github_installations import (
    GitHubCredentialResolutionError,
    TenantGitHubInstallationCredential,
    is_valid_github_repository,
)


class PostgresTenantGitHubInstallationProvider:
    """Resolve tenant bindings with a dedicated Worker/Verifier database DSN.

    The DSN must authenticate as a login that is a member of the
    jas_si_agent_worker or jas_si_agent_verifier capability role. The database
    routine enforces that identity and returns only an active, verified
    installation/repository binding. A token issuer then mints a short-lived,
    repository-scoped token; no token is stored in PostgreSQL.
    """

    def __init__(
        self,
        *,
        database_dsn: str,
        token_issuer: Any,
        connection_factory: Callable[[str], Any] | None = None,
    ) -> None:
        if not isinstance(database_dsn, str) or not database_dsn.strip():
            raise ValueError("Dedicated agent database DSN is required")
        if token_issuer is None or not callable(getattr(token_issuer, "issue", None)):
            raise ValueError("A trusted GitHub App token issuer is required")
        if connection_factory is not None and not callable(connection_factory):
            raise ValueError("connection_factory must be callable")
        self._database_dsn = database_dsn.strip()
        self._token_issuer = token_issuer
        self._connection_factory = connection_factory

    def _connect(self) -> Any:
        if self._connection_factory is not None:
            return self._connection_factory(self._database_dsn)
        import psycopg

        return psycopg.connect(self._database_dsn)

    def resolve(
        self,
        *,
        tenant_id: UUID,
        repository: str,
    ) -> TenantGitHubInstallationCredential | None:
        """Resolve and mint a credential only for a verified tenant binding."""
        if not isinstance(tenant_id, UUID):
            raise GitHubCredentialResolutionError(
                "Authenticated tenant identity is required"
            )
        if not is_valid_github_repository(repository):
            raise GitHubCredentialResolutionError("Repository identifier is invalid")

        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT tenant_id,installation_id,repository_full_name "
                    "FROM public.jas_si_github_installation_binding_resolve(%s,%s)",
                    (tenant_id, repository),
                )
                row = cursor.fetchone()
        except Exception:
            # Driver errors can include connection strings and deployment details.
            raise GitHubCredentialResolutionError(
                "Tenant GitHub installation binding is unavailable"
            ) from None

        if row is None:
            return None
        if not isinstance(row, (tuple, list)) or len(row) != 3:
            raise GitHubCredentialResolutionError(
                "Tenant GitHub installation binding returned an invalid record"
            )

        bound_tenant_id, installation_id, bound_repository = row
        if bound_tenant_id != tenant_id:
            raise GitHubCredentialResolutionError(
                "GitHub installation tenant binding mismatch"
            )
        if (
            isinstance(installation_id, bool)
            or not isinstance(installation_id, int)
            or installation_id <= 0
        ):
            raise GitHubCredentialResolutionError(
                "GitHub installation binding returned an invalid installation"
            )
        if (
            not isinstance(bound_repository, str)
            or bound_repository.casefold() != repository.casefold()
            or not is_valid_github_repository(bound_repository)
        ):
            raise GitHubCredentialResolutionError(
                "GitHub installation repository binding mismatch"
            )

        try:
            issued = self._token_issuer.issue(
                installation_id=installation_id,
                repository=bound_repository,
            )
        except Exception:
            # Never expose JWT, private-key, HTTP header, or provider exception data.
            raise GitHubCredentialResolutionError(
                "Tenant GitHub installation credential is unavailable"
            ) from None

        try:
            if (
                issued.installation_id != installation_id
                or issued.repository.casefold() != bound_repository.casefold()
                or issued.expires_at.tzinfo is None
                or issued.expires_at.utcoffset() is None
            ):
                raise ValueError("Issuer response binding mismatch")
            return TenantGitHubInstallationCredential(
                tenant_id=tenant_id,
                installation_id=installation_id,
                repository=bound_repository,
                access_token=issued.access_token,
                expires_at=issued.expires_at.astimezone(timezone.utc),
            )
        except Exception:
            raise GitHubCredentialResolutionError(
                "GitHub installation token issuer returned an invalid credential"
            ) from None


__all__ = ["PostgresTenantGitHubInstallationProvider"]
