"""GitHub App user OAuth authorization primitives with PKCE.

This module creates and validates protocol material only. A production caller
must persist the state digest, tenant/account binding, expiry, and encrypted
PKCE verifier in a durable single-use store before redirecting the browser.
The callback must atomically consume that record before exchanging its code.
No tenant identity or Installation ownership is inferred from callback input.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

_GITHUB_AUTHORIZE_ENDPOINT = "https://github.com/login/oauth/authorize"
_STATE_BYTES = 32
_VERIFIER_BYTES = 32
_CODE_RE = re.compile(r"^[A-Za-z0-9._~-]{1,512}$")
_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_]{1,128}$")
_STATE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_VERIFIER_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")


class GitHubOAuthError(ValueError):
    """OAuth request or callback material is invalid."""


@dataclass(frozen=True)
class GitHubOAuthAttempt:
    state: str
    state_digest: bytes
    code_verifier: str
    code_challenge: str
    code_challenge_method: str = "S256"

    def __repr__(self) -> str:
        return (
            "GitHubOAuthAttempt(state=<redacted>, state_digest=<redacted>, "
            "code_verifier=<redacted>, code_challenge=<redacted>, "
            "code_challenge_method='S256')"
        )


@dataclass(frozen=True)
class GitHubOAuthAuthorizationRequest:
    authorization_url: str
    state_digest: bytes
    code_verifier: str
    state: str

    def __repr__(self) -> str:
        return (
            "GitHubOAuthAuthorizationRequest(authorization_url=<redacted>, "
            "state_digest=<redacted>, code_verifier=<redacted>, state=<redacted>)"
        )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _validate_redirect_uri(redirect_uri: str) -> str:
    if not isinstance(redirect_uri, str) or len(redirect_uri) > 2048:
        raise GitHubOAuthError("OAuth redirect URI is invalid")
    try:
        parsed = urlsplit(redirect_uri)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise GitHubOAuthError("OAuth redirect URI is invalid") from None
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise GitHubOAuthError("OAuth redirect URI must be an HTTPS callback URL")
    return redirect_uri


def create_github_oauth_attempt() -> GitHubOAuthAttempt:
    """Create high-entropy state and an RFC 7636 S256 PKCE challenge."""
    state = _b64url(secrets.token_bytes(_STATE_BYTES))
    verifier = _b64url(secrets.token_bytes(_VERIFIER_BYTES))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return GitHubOAuthAttempt(
        state=state,
        state_digest=hashlib.sha256(state.encode("ascii")).digest(),
        code_verifier=verifier,
        code_challenge=challenge,
    )


def build_github_oauth_authorization_request(
    *,
    client_id: str,
    redirect_uri: str,
    attempt: GitHubOAuthAttempt,
) -> GitHubOAuthAuthorizationRequest:
    """Build GitHub's authorization URL using PKCE S256 and opaque state.

    Persist attempt.state_digest and an authenticated-encrypted copy of
    attempt.code_verifier with the authenticated tenant/account IDs and a
    short expiry before returning the URL to a browser.
    """
    if not isinstance(client_id, str) or not _CLIENT_ID_RE.fullmatch(client_id):
        raise GitHubOAuthError("GitHub OAuth client ID is invalid")
    callback = _validate_redirect_uri(redirect_uri)
    if not isinstance(attempt, GitHubOAuthAttempt):
        raise GitHubOAuthError("GitHub OAuth attempt is invalid")
    if (
        not isinstance(attempt.state, str)
        or not _STATE_RE.fullmatch(attempt.state)
        or not isinstance(attempt.state_digest, bytes)
        or len(attempt.state_digest) != 32
        or not isinstance(attempt.code_verifier, str)
        or not _VERIFIER_RE.fullmatch(attempt.code_verifier)
        or not isinstance(attempt.code_challenge, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", attempt.code_challenge)
        or not hmac.compare_digest(
            hashlib.sha256(attempt.state.encode("ascii")).digest(),
            attempt.state_digest,
        )
        or not hmac.compare_digest(
            _b64url(hashlib.sha256(attempt.code_verifier.encode("ascii")).digest()),
            attempt.code_challenge,
        )
        or attempt.code_challenge_method != "S256"
    ):
        raise GitHubOAuthError("GitHub OAuth PKCE attempt is invalid")

    query = urlencode({
        "client_id": client_id,
        "redirect_uri": callback,
        "state": attempt.state,
        "code_challenge": attempt.code_challenge,
        "code_challenge_method": "S256",
    })
    return GitHubOAuthAuthorizationRequest(
        authorization_url=f"{_GITHUB_AUTHORIZE_ENDPOINT}?{query}",
        state_digest=attempt.state_digest,
        code_verifier=attempt.code_verifier,
        state=attempt.state,
    )


def validate_github_oauth_callback(
    *,
    supplied_state: str,
    expected_state_digest: bytes,
    authorization_code: str,
) -> str:
    """Validate callback state and authorization code before token exchange.

    expected_state_digest must come from a durable, unexpired, tenant-bound
    record atomically claimed/consumed by the callback handler. This pure
    function does not provide replay protection by itself.
    """
    if (
        not isinstance(supplied_state, str)
        or not _STATE_RE.fullmatch(supplied_state)
        or not isinstance(expected_state_digest, bytes)
        or len(expected_state_digest) != 32
    ):
        raise GitHubOAuthError("GitHub OAuth state is invalid")
    actual_digest = hashlib.sha256(supplied_state.encode("ascii")).digest()
    if not hmac.compare_digest(actual_digest, expected_state_digest):
        raise GitHubOAuthError("GitHub OAuth state verification failed")
    if not isinstance(authorization_code, str) or not _CODE_RE.fullmatch(authorization_code):
        raise GitHubOAuthError("GitHub OAuth authorization code is invalid")
    return authorization_code
