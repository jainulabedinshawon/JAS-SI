"""Strict GitHub OAuth code exchange and authenticated-user lookup.

The short-lived user token is held only in memory for the identity check. This
module does not persist it, log it, or treat OAuth identity as Installation
ownership proof.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx


_TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"
_USER_ENDPOINT = "https://api.github.com/user"
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_]{20,512}$")
_LOGIN_RE = re.compile(r"^[A-Za-z0-9-]{1,39}$")


class GitHubOAuthProviderError(ValueError):
    """GitHub OAuth provider response failed validation."""


@dataclass(frozen=True)
class GitHubAuthenticatedUser:
    github_user_id: int
    login: str
    name: str | None = None


@dataclass(frozen=True)
class _GitHubOAuthToken:
    access_token: str = field(repr=False)

    def __repr__(self) -> str:
        return "_GitHubOAuthToken(access_token=<redacted>)"


class GitHubOAuthProvider:
    """Exchange one code with PKCE, then identify its user via GitHub /user."""

    def __init__(
        self, *, client_id: str, client_secret: str,
        timeout_seconds: float = 8.0, transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not isinstance(client_id, str) or not 1 <= len(client_id) <= 128:
            raise GitHubOAuthProviderError("GitHub OAuth client ID is unavailable")
        if not isinstance(client_secret, str) or not 20 <= len(client_secret) <= 512:
            raise GitHubOAuthProviderError("GitHub OAuth client secret is unavailable")
        if not isinstance(timeout_seconds, (int, float)) or not 1 <= timeout_seconds <= 15:
            raise GitHubOAuthProviderError("GitHub OAuth provider timeout is invalid")
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = float(timeout_seconds)
        self._transport = transport

    def _client(self) -> httpx.Client:
        return httpx.Client(
            timeout=httpx.Timeout(self._timeout),
            follow_redirects=False,
            transport=self._transport,
            headers={"User-Agent": "JAS-SI-GitHub-OAuth", "Accept": "application/json"},
        )

    def exchange_code(
        self, *, code: str, code_verifier: str, redirect_uri: str,
    ) -> _GitHubOAuthToken:
        if not isinstance(code, str) or not 1 <= len(code) <= 512:
            raise GitHubOAuthProviderError("GitHub authorization code is invalid")
        if not isinstance(code_verifier, str) or not 43 <= len(code_verifier) <= 128:
            raise GitHubOAuthProviderError("GitHub PKCE verifier is invalid")
        if not isinstance(redirect_uri, str) or not redirect_uri.startswith("https://"):
            raise GitHubOAuthProviderError("GitHub OAuth redirect URI is invalid")
        try:
            with self._client() as client:
                response = client.post(
                    _TOKEN_ENDPOINT,
                    data={
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                        "code": code,
                        "redirect_uri": redirect_uri,
                        "code_verifier": code_verifier,
                    },
                )
                response.raise_for_status()
                payload: Any = response.json()
        except (httpx.HTTPError, ValueError):
            raise GitHubOAuthProviderError(
                "GitHub authorization code exchange failed"
            ) from None
        if not isinstance(payload, dict) or payload.get("error"):
            raise GitHubOAuthProviderError("GitHub rejected the authorization code")
        token = payload.get("access_token")
        token_type = payload.get("token_type")
        if (
            not isinstance(token, str)
            or not _TOKEN_RE.fullmatch(token)
            or not isinstance(token_type, str)
            or token_type.lower() != "bearer"
        ):
            raise GitHubOAuthProviderError("GitHub token response is invalid")
        return _GitHubOAuthToken(access_token=token)

    def authenticated_user(self, token: _GitHubOAuthToken) -> GitHubAuthenticatedUser:
        if not isinstance(token, _GitHubOAuthToken) or not _TOKEN_RE.fullmatch(token.access_token):
            raise GitHubOAuthProviderError("GitHub access token is invalid")
        try:
            with self._client() as client:
                response = client.get(
                    _USER_ENDPOINT,
                    headers={"Authorization": f"Bearer {token.access_token}"},
                )
                response.raise_for_status()
                payload: Any = response.json()
        except (httpx.HTTPError, ValueError):
            raise GitHubOAuthProviderError(
                "GitHub authenticated-user verification failed"
            ) from None
        if not isinstance(payload, dict):
            raise GitHubOAuthProviderError("GitHub user response is invalid")
        user_id, login, name = payload.get("id"), payload.get("login"), payload.get("name")
        if (
            not isinstance(user_id, int) or isinstance(user_id, bool) or user_id <= 0
            or not isinstance(login, str) or not _LOGIN_RE.fullmatch(login)
            or (name is not None and not isinstance(name, str))
        ):
            raise GitHubOAuthProviderError("GitHub user identity response is invalid")
        return GitHubAuthenticatedUser(github_user_id=user_id, login=login, name=name)
