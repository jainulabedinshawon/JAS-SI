"""Read-only authoritative GitHub App Installation and repository discovery.

This adapter signs short-lived App JWTs in memory, checks the live Installation
record, and obtains the exact repository set from GitHub's Installation API.
It never trusts webhook payload account/repository fields and never persists
or logs App or Installation access tokens.
"""
from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_GITHUB_API = "https://api.github.com"
_API_VERSION = "2022-11-28"
_PAGE_SIZE = 100
_MAX_PAGES = 100
_TOKEN_RE = re.compile(r"^ghs_[A-Za-z0-9_]{20,512}$")
_LOGIN_RE = re.compile(r"^(?![A-Za-z0-9-]*--)[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPOSITORY_RE = re.compile(
    r"^((?![A-Za-z0-9-]*--)[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)/([A-Za-z0-9_.-]{1,100})$"
)


class GitHubAppAPIError(RuntimeError):
    """Authoritative GitHub App API evidence is unavailable or invalid."""


@dataclass(frozen=True)
class GitHubInstallationRepository:
    repository_id: int
    full_name: str
    private: bool


@dataclass(frozen=True)
class GitHubInstallationSnapshot:
    installation_id: int
    app_id: int
    account_id: int
    account_login: str
    account_type: str
    suspended: bool
    repositories: tuple[GitHubInstallationRepository, ...] = ()


@dataclass(frozen=True)
class _InstallationToken:
    value: str = field(repr=False)
    expires_at: datetime

    def __repr__(self) -> str:
        return "_InstallationToken(value=<redacted>)"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _positive_id(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GitHubAppAPIError(f"GitHub {field_name} is invalid")
    return value


def _parse_expiry(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise GitHubAppAPIError("GitHub Installation token expiry is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise GitHubAppAPIError("GitHub Installation token expiry is invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GitHubAppAPIError("GitHub Installation token expiry is invalid")
    return parsed.astimezone(timezone.utc)


class GitHubAppInstallationAPI:
    """Verify an Installation and fetch its current repository allowlist.

    The private key is held only in process memory. Callers should instantiate
    this adapter in a restricted reconciliation worker, never in public API
    request handlers. GitHub's response, not webhook JSON, is authoritative.
    """

    def __init__(
        self,
        *,
        app_id: int,
        private_key_pem: bytes,
        transport: httpx.BaseTransport | None = None,
        timeout_seconds: float = 8.0,
        max_pages: int = _MAX_PAGES,
        clock=None,
    ) -> None:
        self._app_id = _positive_id(app_id, "App ID")
        if not isinstance(private_key_pem, bytes) or not private_key_pem:
            raise ValueError("GitHub App private key is required")
        if not isinstance(timeout_seconds, (int, float)) or not 1 <= timeout_seconds <= 15:
            raise ValueError("GitHub App API timeout must be between 1 and 15 seconds")
        if isinstance(max_pages, bool) or not isinstance(max_pages, int) or not 1 <= max_pages <= _MAX_PAGES:
            raise ValueError("GitHub repository pagination bound is invalid")
        try:
            key = serialization.load_pem_private_key(private_key_pem, password=None)
        except (TypeError, ValueError):
            raise ValueError("GitHub App private key is invalid") from None
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise ValueError("GitHub App private key must be RSA 2048-bit or stronger")
        self._private_key = key
        self._transport = transport
        self._timeout = float(timeout_seconds)
        self._max_pages = max_pages
        self._clock = clock or time.time

    def _app_jwt(self) -> str:
        now = int(self._clock())
        header = _b64url(json.dumps(
            {"alg": "RS256", "typ": "JWT"}, separators=(",", ":"), sort_keys=True
        ).encode("utf-8"))
        payload = _b64url(json.dumps(
            {"iat": now - 60, "exp": now + 540, "iss": self._app_id},
            separators=(",", ":"), sort_keys=True,
        ).encode("utf-8"))
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = self._private_key.sign(
            signing_input, padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{header}.{payload}.{_b64url(signature)}"

    def _client(self) -> httpx.Client:
        return httpx.Client(
            timeout=httpx.Timeout(self._timeout),
            follow_redirects=False,
            transport=self._transport,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": _API_VERSION,
                "User-Agent": "JAS-SI-GitHub-App-Reconciler",
            },
        )

    def snapshot(self, *, installation_id: int) -> GitHubInstallationSnapshot | None:
        """Return current App/Installation/account/repository facts, or None on 404."""
        installation_id = _positive_id(installation_id, "Installation ID")
        try:
            with self._client() as client:
                app_jwt = self._app_jwt()
                app_headers = {"Authorization": f"Bearer {app_jwt}"}
                response = client.get(
                    f"{_GITHUB_API}/app/installations/{installation_id}",
                    headers=app_headers,
                )
                if response.status_code == 404:
                    return None
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise GitHubAppAPIError("GitHub Installation response is invalid")
                returned_id = _positive_id(data.get("id"), "Installation ID")
                returned_app_id = _positive_id(data.get("app_id"), "Installation App ID")
                if returned_id != installation_id or returned_app_id != self._app_id:
                    raise GitHubAppAPIError("GitHub Installation does not belong to the configured App")
                account = data.get("account")
                if not isinstance(account, dict):
                    raise GitHubAppAPIError("GitHub Installation account is invalid")
                account_id = _positive_id(account.get("id"), "account ID")
                account_login = account.get("login")
                account_type = account.get("type")
                if (
                    not isinstance(account_login, str)
                    or not _LOGIN_RE.fullmatch(account_login)
                    or account_type not in {"User", "Organization"}
                ):
                    raise GitHubAppAPIError("GitHub Installation account identity is invalid")
                suspended_at = data.get("suspended_at")
                if suspended_at is not None and not isinstance(suspended_at, str):
                    raise GitHubAppAPIError("GitHub Installation suspension state is invalid")
                if suspended_at is not None:
                    return GitHubInstallationSnapshot(
                        installation_id, returned_app_id, account_id,
                        account_login, account_type, True, (),
                    )

                token = self._create_installation_token(client, app_headers, installation_id)
                repositories = self._list_repositories(client, token)
                return GitHubInstallationSnapshot(
                    installation_id, returned_app_id, account_id,
                    account_login, account_type, False, repositories,
                )
        except GitHubAppAPIError:
            raise
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            raise GitHubAppAPIError(
                "Authoritative GitHub Installation reconciliation failed"
            ) from None
        except Exception:
            raise GitHubAppAPIError(
                "Authoritative GitHub Installation reconciliation failed"
            ) from None

    def _create_installation_token(
        self, client: httpx.Client, app_headers: dict[str, str], installation_id: int,
    ) -> _InstallationToken:
        response = client.post(
            f"{_GITHUB_API}/app/installations/{installation_id}/access_tokens",
            headers=app_headers,
            json={},
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise GitHubAppAPIError("GitHub Installation token response is invalid")
        value = payload.get("token")
        expires_at = _parse_expiry(payload.get("expires_at"))
        now = datetime.now(timezone.utc)
        if (
            not isinstance(value, str)
            or not _TOKEN_RE.fullmatch(value)
            or expires_at <= now
            or expires_at > now + timedelta(hours=1, minutes=5)
        ):
            raise GitHubAppAPIError("GitHub Installation token response is invalid")
        return _InstallationToken(value, expires_at)

    def _list_repositories(
        self, client: httpx.Client, token: _InstallationToken,
    ) -> tuple[GitHubInstallationRepository, ...]:
        headers = {"Authorization": f"Bearer {token.value}"}
        expected_count: int | None = None
        seen_ids: set[int] = set()
        seen_names: set[str] = set()
        repositories: list[GitHubInstallationRepository] = []
        for page in range(1, self._max_pages + 1):
            response = client.get(
                f"{_GITHUB_API}/installation/repositories",
                headers=headers,
                params={"per_page": _PAGE_SIZE, "page": page},
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("repositories"), list):
                raise GitHubAppAPIError("GitHub repository response is invalid")
            count = payload.get("total_count")
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise GitHubAppAPIError("GitHub repository count is invalid")
            if count > self._max_pages * _PAGE_SIZE:
                raise GitHubAppAPIError("GitHub repository list exceeds the verification bound")
            if expected_count is None:
                expected_count = count
            elif count != expected_count:
                raise GitHubAppAPIError("GitHub repository list changed during reconciliation")
            items = payload["repositories"]
            if len(items) > _PAGE_SIZE:
                raise GitHubAppAPIError("GitHub repository page exceeds the requested bound")
            for item in items:
                if not isinstance(item, dict):
                    raise GitHubAppAPIError("GitHub repository entry is invalid")
                repository_id = _positive_id(item.get("id"), "repository ID")
                full_name = item.get("full_name")
                private = item.get("private")
                if (
                    not isinstance(full_name, str)
                    or not _REPOSITORY_RE.fullmatch(full_name)
                    or not isinstance(private, bool)
                    or repository_id in seen_ids
                    or full_name.casefold() in seen_names
                ):
                    raise GitHubAppAPIError("GitHub repository entry is invalid or duplicated")
                seen_ids.add(repository_id)
                seen_names.add(full_name.casefold())
                repositories.append(GitHubInstallationRepository(repository_id, full_name, private))
            if len(repositories) == expected_count:
                return tuple(repositories)
            if not items:
                raise GitHubAppAPIError("GitHub repository list was incomplete")
        raise GitHubAppAPIError("GitHub repository pagination exceeded its bound")
