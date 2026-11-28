"""Least-privilege GitHub App installation-token issuance.

This module only mints short-lived, repository-scoped, read-only tokens.
It deliberately does not map tenants to installations: that mapping must be
resolved by a separately trusted persistence adapter before this issuer is
called. Never pass user-supplied installation IDs to this class.
"""
from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from jas_si_agent.github_installations import (
    TenantGitHubInstallationCredential,
    TenantGitHubInstallationProvider,
    is_valid_github_repository,
)

_GITHUB_API = "https://api.github.com"
_API_VERSION = "2022-11-28"
_REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_TOKEN_TTL_LIMIT = timedelta(hours=1, minutes=5)
# The immutable commit/file reader uses only the GitHub Contents API.
# GitHub supplies metadata:read implicitly for repository-scoped installation
# tokens, so do not request unrelated Actions, Checks, PR, or Status scopes.
_READ_ONLY_PERMISSIONS = {
    "contents": "read",
}


class GitHubAppTokenError(RuntimeError):
    """A GitHub App token could not be safely issued."""


@dataclass(frozen=True)
class GitHubAppTokenSettings:
    app_id: int
    private_key_path: str | None = None
    private_key_pem: bytes | None = field(default=None, repr=False)
    api_base_url: str = _GITHUB_API
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        if isinstance(self.app_id, bool) or not isinstance(self.app_id, int) or self.app_id <= 0:
            raise ValueError("GitHub App ID must be a positive integer")
        if (self.private_key_path is None) == (self.private_key_pem is None):
            raise ValueError("Configure exactly one GitHub App private-key source")
        if self.private_key_path is not None and (
            not isinstance(self.private_key_path, str) or not self.private_key_path.strip()
        ):
            raise ValueError("GitHub App private key path is invalid")
        if self.private_key_pem is not None and (
            not isinstance(self.private_key_pem, bytes)
            or len(self.private_key_pem) > 18000
            or not self.private_key_pem.startswith(b"-----BEGIN ")
            or b"PRIVATE KEY-----" not in self.private_key_pem[:80]
        ):
            raise ValueError("GitHub App private key PEM is invalid")
        if self.api_base_url != _GITHUB_API:
            raise ValueError("GitHub API base URL must use the official HTTPS endpoint")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not 1 <= self.timeout_seconds <= 30
        ):
            raise ValueError("GitHub API timeout must be between 1 and 30 seconds")


@dataclass(frozen=True)
class IssuedGitHubInstallationToken:
    installation_id: int
    repository: str
    access_token: str = field(repr=False, compare=False)
    expires_at: datetime

    def __post_init__(self) -> None:
        if isinstance(self.installation_id, bool) or not isinstance(self.installation_id, int) or self.installation_id <= 0:
            raise ValueError("installation_id must be a positive integer")
        if not is_valid_github_repository(self.repository):
            raise ValueError("repository must be an owner/name identifier")
        if (
            not isinstance(self.access_token, str)
            or not self.access_token
            or len(self.access_token) > 4096
            or self.access_token.strip() != self.access_token
            or any(ord(char) < 33 or ord(char) > 126 for char in self.access_token)
        ):
            raise ValueError("GitHub installation token is invalid")
        if not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_github_app_private_key_b64(raw: str) -> bytes:
    """Decode a bounded base64 PEM value without exposing secret material."""
    if not isinstance(raw, str) or not raw or len(raw) > 24000:
        raise GitHubAppTokenError("GitHub App private key configuration is invalid")
    try:
        pem = base64.b64decode(raw, validate=True)
    except Exception:
        raise GitHubAppTokenError("GitHub App private key configuration is invalid") from None
    if (
        len(pem) > 18000
        or not pem.startswith(b"-----BEGIN ")
        or b"PRIVATE KEY-----" not in pem[:80]
    ):
        raise GitHubAppTokenError("GitHub App private key configuration is invalid")
    return pem


def _load_rsa_private_key(path: str | None, pem_bytes: bytes | None = None) -> rsa.RSAPrivateKey:
    try:
        pem = pem_bytes if pem_bytes is not None else Path(path).read_bytes()
        key = serialization.load_pem_private_key(pem, password=None)
    except Exception:
        raise GitHubAppTokenError("GitHub App private key could not be loaded") from None
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise GitHubAppTokenError("GitHub App private key must be RSA 2048-bit or stronger")
    return key


class GitHubAppInstallationTokenIssuer:
    """Mint a read-only token for one explicitly allowlisted repository.

    The caller must establish installation ownership and tenant binding before
    invoking issue(). The response is checked for repository scope and expiry.
    """

    def __init__(
        self,
        settings: GitHubAppTokenSettings,
        *,
        http_client: httpx.Client | None = None,
        clock=time.time,
    ) -> None:
        self._settings = settings
        self._client = http_client
        self._clock = clock

    def _create_app_jwt(self) -> str:
        key = _load_rsa_private_key(self._settings.private_key_path, self._settings.private_key_pem)
        now = int(self._clock())
        header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
        payload = _b64url(json.dumps(
            {"iss": str(self._settings.app_id), "iat": now - 60, "exp": now + 540},
            separators=(",", ":"),
        ).encode())
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{payload}.{_b64url(signature)}"

    def issue(self, *, installation_id: int, repository: str) -> IssuedGitHubInstallationToken:
        if isinstance(installation_id, bool) or not isinstance(installation_id, int) or installation_id <= 0:
            raise GitHubAppTokenError("GitHub installation ID is invalid")
        if not is_valid_github_repository(repository):
            raise GitHubAppTokenError("GitHub repository identifier is invalid")
        owner, repo_name = repository.split("/", 1)
        if not _REPOSITORY_NAME.fullmatch(repo_name):
            raise GitHubAppTokenError("GitHub repository identifier is invalid")

        payload = {
            "repositories": [repo_name],
            "permissions": dict(_READ_ONLY_PERMISSIONS),
        }
        url = f"{_GITHUB_API}/app/installations/{installation_id}/access_tokens"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._create_app_jwt()}",
            "X-GitHub-Api-Version": _API_VERSION,
            "Content-Type": "application/json",
        }
        client = self._client or httpx.Client(timeout=self._settings.timeout_seconds)
        try:
            response = client.post(url, headers=headers, json=payload)
            if response.status_code != 201:
                raise GitHubAppTokenError(f"GitHub installation token request failed (HTTP {response.status_code})")
            data: Any = response.json()
        except GitHubAppTokenError:
            raise
        except Exception:
            # Do not propagate HTTP/client exceptions: they can contain request
            # headers, URLs, or other sensitive deployment details.
            raise GitHubAppTokenError("GitHub installation token request failed") from None
        finally:
            if self._client is None:
                client.close()

        try:
            token = data["token"]
            expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
            returned_repositories = data["repositories"]
            returned_permissions = data["permissions"]
            returned_repository_names = {
                str(item.get("full_name", "")).casefold()
                for item in returned_repositories
                if isinstance(item, dict)
            }
            repository_match = returned_repository_names == {repository.casefold()}
            # GitHub may include its implicit metadata:read permission. No
            # additional permission or write-level access is accepted.
            permissions_match = (
                all(returned_permissions.get(name) == access
                    for name, access in _READ_ONLY_PERMISSIONS.items())
                and all(
                    name in {*_READ_ONLY_PERMISSIONS, "metadata"}
                    and access == "read"
                    for name, access in returned_permissions.items()
                )
            )
            now = datetime.fromtimestamp(self._clock(), timezone.utc)
            if not repository_match or not permissions_match:
                raise ValueError("scope mismatch")
            if expires_at.tzinfo is None or expires_at <= now or expires_at > now + _TOKEN_TTL_LIMIT:
                raise ValueError("invalid expiry")
            return IssuedGitHubInstallationToken(
                installation_id=installation_id,
                repository=f"{owner}/{repo_name}",
                access_token=token,
                expires_at=expires_at,
            )
        except Exception:
            raise GitHubAppTokenError("GitHub returned an invalid or over-scoped installation token") from None



@dataclass(frozen=True)
class TenantGitHubInstallationBinding:
    """Trusted persistence result binding one tenant to one installed repo."""

    tenant_id: UUID
    installation_id: int
    repository: str


class TenantGitHubInstallationBindingResolver(Protocol):
    """Database/admin adapter; must return only verified tenant-owned bindings."""

    def resolve(
        self, *, tenant_id: UUID, repository: str
    ) -> TenantGitHubInstallationBinding | None:
        """Resolve an already verified installation/repository binding."""


class PostgresTenantGitHubInstallationBindingResolver:
    """Resolve only active verified bindings through the DB-owned routine.

    The supplied DSN must be a dedicated Worker or Verifier login that is a
    member of exactly its own capability role. This adapter never reads the
    installation mapping tables directly.
    """

    def __init__(self, database_dsn: str) -> None:
        if not isinstance(database_dsn, str) or not database_dsn.strip():
            raise ValueError("A dedicated agent-host database DSN is required")
        self._database_dsn = database_dsn

    def resolve(
        self, *, tenant_id: UUID, repository: str
    ) -> TenantGitHubInstallationBinding | None:
        if not isinstance(tenant_id, UUID):
            raise GitHubAppTokenError("Authenticated tenant identity is required")
        if not is_valid_github_repository(repository):
            raise GitHubAppTokenError("Repository identifier is invalid")
        try:
            import psycopg

            with psycopg.connect(self._database_dsn, connect_timeout=5) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """SELECT tenant_id,installation_id,repository_full_name
                             FROM public.jas_si_github_installation_binding_resolve(%s,%s)""",
                        (tenant_id, repository),
                    )
                    row = cursor.fetchone()
        except Exception:
            raise GitHubAppTokenError(
                "Tenant GitHub installation binding lookup failed"
            ) from None
        if row is None:
            return None
        try:
            return TenantGitHubInstallationBinding(
                tenant_id=row[0],
                installation_id=row[1],
                repository=row[2],
            )
        except Exception:
            raise GitHubAppTokenError(
                "Tenant GitHub installation binding result is invalid"
            ) from None


def build_github_app_tenant_credential_provider(
    *, database_dsn: str, app_id: int, private_key_path: str
) -> "GitHubAppTenantCredentialProvider":
    """Build a host-local provider from injected, non-user-controlled config."""
    resolver = PostgresTenantGitHubInstallationBindingResolver(database_dsn)
    issuer = GitHubAppInstallationTokenIssuer(
        GitHubAppTokenSettings(
            app_id=app_id,
            private_key_path=private_key_path,
        )
    )
    return GitHubAppTenantCredentialProvider(
        binding_resolver=resolver,
        token_issuer=issuer,
    )



class GitHubAppTenantCredentialProvider(TenantGitHubInstallationProvider):
    """Bridge trusted tenant-installation records to short-lived App tokens.

    The resolver is the security boundary: it must authenticate installation
    ownership and repository allowlisting from trusted records. This provider
    never accepts an installation ID from task payloads or user input.
    """

    def __init__(
        self,
        *,
        binding_resolver: TenantGitHubInstallationBindingResolver,
        token_issuer: GitHubAppInstallationTokenIssuer,
    ) -> None:
        if binding_resolver is None or not callable(getattr(binding_resolver, "resolve", None)):
            raise ValueError("A trusted tenant installation binding resolver is required")
        if token_issuer is None or not callable(getattr(token_issuer, "issue", None)):
            raise ValueError("A GitHub App token issuer is required")
        self._binding_resolver = binding_resolver
        self._token_issuer = token_issuer

    def resolve(
        self, *, tenant_id: UUID, repository: str
    ) -> TenantGitHubInstallationCredential | None:
        if not isinstance(tenant_id, UUID):
            raise GitHubAppTokenError("Authenticated tenant identity is required")
        if not is_valid_github_repository(repository):
            raise GitHubAppTokenError("Repository identifier is invalid")
        try:
            binding = self._binding_resolver.resolve(
                tenant_id=tenant_id, repository=repository
            )
        except Exception:
            raise GitHubAppTokenError("Tenant GitHub installation binding is unavailable") from None
        if binding is None:
            return None
        if not isinstance(binding, TenantGitHubInstallationBinding):
            raise GitHubAppTokenError("Tenant GitHub installation binding is invalid")
        if (
            binding.tenant_id != tenant_id
            or not is_valid_github_repository(binding.repository)
            or binding.repository.casefold() != repository.casefold()
            or isinstance(binding.installation_id, bool)
            or not isinstance(binding.installation_id, int)
            or binding.installation_id <= 0
        ):
            raise GitHubAppTokenError("Tenant GitHub installation binding mismatch")
        issued = self._token_issuer.issue(
            installation_id=binding.installation_id,
            repository=repository,
        )
        return TenantGitHubInstallationCredential(
            tenant_id=tenant_id,
            installation_id=binding.installation_id,
            repository=repository,
            access_token=issued.access_token,
            expires_at=issued.expires_at,
        )

__all__ = [
    "GitHubAppInstallationTokenIssuer",
    "GitHubAppTenantCredentialProvider",
    "TenantGitHubInstallationBinding",
    "TenantGitHubInstallationBindingResolver",
    "PostgresTenantGitHubInstallationBindingResolver",
    "build_github_app_tenant_credential_provider",
    "GitHubAppTokenError",
    "GitHubAppTokenSettings",
    "IssuedGitHubInstallationToken",
    "decode_github_app_private_key_b64",
]
