"""Fail-closed task-scoped GitHub Capability Broker database adapter.

This service resolves capability metadata only. It does not mint or return
GitHub tokens, execute repository reads, or accept workload identity from
request-controlled fields.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg.conninfo import conninfo_to_dict


class GitHubCapabilityBrokerError(RuntimeError):
    """A task capability could not be safely resolved."""


@dataclass(frozen=True)
class ResolvedGitHubTaskCapability:
    task_id: UUID
    tenant_id: UUID
    installation_id: int
    repository_full_name: str
    capability_role: str
    expires_at: datetime
    commit_sha: str
    repository_paths: list[str]


class PostgresGitHubCapabilityBroker:
    """Use a dedicated Broker login and the narrow SECURITY DEFINER resolver."""

    def __init__(self, database_url: str, *, connect_timeout: int = 5) -> None:
        if not isinstance(database_url, str) or not database_url.strip():
            raise ValueError("Broker database URL is required")
        if isinstance(connect_timeout, bool) or not 1 <= connect_timeout <= 15:
            raise ValueError("Broker database connect timeout is invalid")
        try:
            options = conninfo_to_dict(database_url)
        except Exception:
            raise ValueError("Broker database URL is invalid") from None
        # Do not allow an accidental plaintext or non-verifying database link.
        if options.get("sslmode") != "verify-full":
            raise ValueError("Broker database connection must require sslmode=verify-full")
        self._database_url = database_url
        self._connect_timeout = connect_timeout

    def resolve(
        self,
        *,
        task_id: UUID,
        principal_id: str,
        role: str,
        lease_fence: int | None = None,
        verifier_claim_token: UUID | None = None,
    ) -> ResolvedGitHubTaskCapability | None:
        if not isinstance(task_id, UUID):
            raise GitHubCapabilityBrokerError("Task identifier is invalid")
        if not isinstance(principal_id, str) or not principal_id:
            raise GitHubCapabilityBrokerError("Authenticated workload identity is required")
        if role == "worker":
            if (isinstance(lease_fence, bool) or not isinstance(lease_fence, int)
                    or lease_fence < 1 or verifier_claim_token is not None):
                raise GitHubCapabilityBrokerError("Worker lease fence is required")
        elif role == "verifier":
            if not isinstance(verifier_claim_token, UUID) or lease_fence is not None:
                raise GitHubCapabilityBrokerError("Verifier claim token is required")
        else:
            raise GitHubCapabilityBrokerError("Workload role is not authorized")

        try:
            with psycopg.connect(
                self._database_url,
                connect_timeout=self._connect_timeout,
                application_name="jas-si-github-capability-broker",
            ) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SET ROLE jas_si_agent_capability_broker")
                    cursor.execute(
                        """
                        SELECT task_id, tenant_id, installation_id,
                               repository_full_name, capability_role,
                               lease_fence, verifier_claim_token, expires_at,
                               commit_sha, repository_paths
                          FROM public.jas_si_github_task_capability_resolve(
                               %s, %s::name, %s, %s, %s
                          )
                        """,
                        (
                            task_id,
                            principal_id,
                            role,
                            lease_fence,
                            verifier_claim_token,
                        ),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        return None
                    paths: Any = row[9]
                    if not isinstance(paths, list) or not 1 <= len(paths) <= 10:
                        raise GitHubCapabilityBrokerError("Persisted repository path scope is invalid")
                    if any(
                        not isinstance(path, str)
                        or not path
                        or len(path) > 500
                        or path.startswith("/")
                        or "\\" in path
                        or "\\x00" in path
                        or any(part in {"", ".", ".."} for part in path.split("/"))
                        for path in paths
                    ):
                        raise GitHubCapabilityBrokerError("Persisted repository path scope is invalid")
                    if (
                        not isinstance(row[7], datetime)
                        or not isinstance(row[8], str)
                        or len(row[8]) != 40
                        or any(char not in "0123456789abcdef" for char in row[8])
                    ):
                        raise GitHubCapabilityBrokerError("Persisted task capability metadata is invalid")
                    return ResolvedGitHubTaskCapability(
                        task_id=row[0],
                        tenant_id=row[1],
                        installation_id=row[2],
                        repository_full_name=row[3],
                        capability_role=row[4],
                        expires_at=row[7],
                        commit_sha=row[8],
                        repository_paths=paths,
                    )
        except GitHubCapabilityBrokerError:
            raise
        except Exception:
            # DB/driver errors can expose DSNs, SQL, or infrastructure details.
            raise GitHubCapabilityBrokerError("Capability authorization is unavailable") from None
