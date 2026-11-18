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
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from jas_si_agent.github_installations import is_valid_github_repository

_GITHUB_API = "https://api.github.com"
_API_VERSION = "2022-11-28"
_REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_TOKEN_TTL_LIMIT = timedelta(hours=1, minutes=5)
_READ_ONLY_PERMISSIONS = {
    "actions": "read",
    "checks": "read",
    "contents": "read",
    "pull_requests": "read",
    "statuses": "read",
}


class GitHubAppTokenError(RuntimeError):
    """A GitHub App token could not be safely issued."""


@dataclass(frozen=True)
class GitHubAppTokenSettings:
    app_id: int
    private_key_path: str
    api_base_url: str = _GITHUB_API
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        if isinstance(self.app_id, bool) or not isinstance(self.app_id, int) or self.app_id <= 0:
            raise ValueError("GitHub App ID must be a positive integer")
        if not isinstance(self.private_key_path, str) or not self.private_key_path.strip():
            raise ValueError("GitHub App private key path is required")
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
        if not isinstance(self.access_token, str) or not self.access_token or len(self.access_token) > 4096:
            raise ValueError("GitHub installation token is invalid")
        if not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _load_rsa_private_key(path: str) -> rsa.RSAPrivateKey:
    try:
        pem = Path(path).read_bytes()
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
        key = _load_rsa_private_key(self._settings.private_key_path)
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
            repository_match = any(
                isinstance(item, dict)
                and str(item.get("full_name", "")).casefold() == repository.casefold()
                for item in returned_repositories
            )
            permissions_match = all(
                returned_permissions.get(name) == access
                for name, access in _READ_ONLY_PERMISSIONS.items()
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


__all__ = [
    "GitHubAppInstallationTokenIssuer",
    "GitHubAppTokenError",
    "GitHubAppTokenSettings",
    "IssuedGitHubInstallationToken",
]
