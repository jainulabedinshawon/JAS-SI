"""Independent proof that an authenticated GitHub user can access an App installation.

This module accepts a short-lived GitHub App user access token obtained by a
separate OAuth authorization-code flow. It never accepts an installation ID
as proof, never trusts webhook payload identity, and never persists the token.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

_GITHUB_API = "https://api.github.com"
_API_VERSION = "2022-11-28"
_PAGE_SIZE = 100
_MAX_PAGES = 100


class GitHubInstallationOwnershipError(RuntimeError):
    """Ownership could not be independently established; callers must fail closed."""


@dataclass(frozen=True)
class GitHubAuthenticatedUser:
    user_id: int
    login: str


@dataclass(frozen=True)
class GitHubInstallationOwnershipProof:
    user: GitHubAuthenticatedUser
    installation_id: int
    app_id: int
    account_id: int
    account_login: str
    account_type: str


class GitHubUserInstallationAccessVerifier:
    """Verify installation visibility through the OAuth-authorized user API.

    The token must be a GitHub App user access token. The verifier checks
    /user first, then exhaustively paginates /user/installations. An installation
    ID supplied by a callback is only a lookup candidate; it is not trusted
    until the exact ID and expected App ID are returned by GitHub.
    """

    def __init__(
        self,
        *,
        expected_app_id: int,
        http_client: httpx.Client | None = None,
        max_pages: int = _MAX_PAGES,
    ) -> None:
        if isinstance(expected_app_id, bool) or not isinstance(expected_app_id, int) or expected_app_id <= 0:
            raise ValueError("Expected GitHub App ID must be a positive integer")
        if isinstance(max_pages, bool) or not isinstance(max_pages, int) or not 1 <= max_pages <= 1000:
            raise ValueError("max_pages must be between 1 and 1000")
        self._expected_app_id = expected_app_id
        self._client = http_client
        self._max_pages = max_pages

    @staticmethod
    def _positive_id(value: Any) -> int:
        # GitHub's JSON API represents IDs as integers. Do not coerce strings,
        # booleans, or floats: int(1.9) would silently truncate malformed data.
        if type(value) is not int or value <= 0:
            raise ValueError("invalid identifier")
        return value

    def verify(
        self,
        *,
        user_access_token: str,
        installation_id: int,
    ) -> GitHubInstallationOwnershipProof:
        if (
            not isinstance(user_access_token, str)
            or not user_access_token
            or user_access_token.strip() != user_access_token
            or len(user_access_token) > 4096
            or any(ord(char) < 33 or ord(char) > 126 for char in user_access_token)
        ):
            raise GitHubInstallationOwnershipError("GitHub user authorization is invalid")
        try:
            candidate_id = self._positive_id(installation_id)
        except (TypeError, ValueError, OverflowError):
            raise GitHubInstallationOwnershipError("GitHub installation ID is invalid") from None

        client = self._client or httpx.Client(timeout=10.0)
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {user_access_token}",
            "X-GitHub-Api-Version": _API_VERSION,
        }
        try:
            user_response = client.get(f"{_GITHUB_API}/user", headers=headers)
            if user_response.status_code != 200:
                raise GitHubInstallationOwnershipError(
                    "GitHub user identity could not be verified"
                )
            user_data = user_response.json()
            user = GitHubAuthenticatedUser(
                user_id=self._positive_id(user_data["id"]),
                login=self._validated_login(user_data["login"]),
            )

            found: dict[str, Any] | None = None
            total_count: int | None = None
            observed = 0
            observed_ids: set[int] = set()
            for page in range(1, self._max_pages + 1):
                response = client.get(
                    f"{_GITHUB_API}/user/installations",
                    headers=headers,
                    params={"per_page": _PAGE_SIZE, "page": page},
                )
                if response.status_code != 200:
                    raise GitHubInstallationOwnershipError(
                        "GitHub Installation access could not be verified"
                    )
                data = response.json()
                if not isinstance(data, dict) or not isinstance(data.get("installations"), list):
                    raise GitHubInstallationOwnershipError(
                        "GitHub Installation response is invalid"
                    )
                count = self._positive_id(data.get("total_count", 0)) if data.get("total_count", 0) else 0
                if total_count is None:
                    total_count = count
                    if total_count > self._max_pages * _PAGE_SIZE:
                        raise GitHubInstallationOwnershipError(
                            "GitHub Installation list exceeds the verification bound"
                        )
                elif count != total_count:
                    raise GitHubInstallationOwnershipError(
                        "GitHub Installation list changed during verification"
                    )
                items = data["installations"]
                for item in items:
                    if not isinstance(item, dict):
                        raise GitHubInstallationOwnershipError(
                            "GitHub Installation entry is invalid"
                        )
                    observed += 1
                    try:
                        item_id = self._positive_id(item.get("id"))
                    except (TypeError, ValueError, OverflowError):
                        raise GitHubInstallationOwnershipError(
                            "GitHub Installation entry is invalid"
                        ) from None
                    if item_id in observed_ids:
                        raise GitHubInstallationOwnershipError(
                            "GitHub returned a duplicate Installation identity"
                        )
                    observed_ids.add(item_id)
                    if item_id == candidate_id:
                        if found is not None:
                            raise GitHubInstallationOwnershipError(
                                "GitHub returned a duplicate Installation identity"
                            )
                        found = item
                if observed >= total_count or len(items) < _PAGE_SIZE:
                    break
            else:
                raise GitHubInstallationOwnershipError(
                    "GitHub Installation list could not be completely verified"
                )

            if observed != (total_count or 0):
                raise GitHubInstallationOwnershipError(
                    "GitHub Installation count did not match the complete response"
                )
            if found is None:
                raise GitHubInstallationOwnershipError(
                    "Authenticated GitHub user cannot access this Installation"
                )
            if self._positive_id(found.get("app_id")) != self._expected_app_id:
                raise GitHubInstallationOwnershipError(
                    "GitHub Installation belongs to a different App"
                )
            account = found.get("account")
            if not isinstance(account, dict):
                raise GitHubInstallationOwnershipError(
                    "GitHub Installation account identity is invalid"
                )
            account_type = account.get("type")
            if account_type not in {"User", "Organization"}:
                raise GitHubInstallationOwnershipError(
                    "GitHub Installation account type is invalid"
                )
            return GitHubInstallationOwnershipProof(
                user=user,
                installation_id=candidate_id,
                app_id=self._expected_app_id,
                account_id=self._positive_id(account.get("id")),
                account_login=self._validated_login(account.get("login")),
                account_type=account_type,
            )
        except GitHubInstallationOwnershipError:
            raise
        except Exception:
            # Never expose HTTP exception text, response bodies, or credentials.
            raise GitHubInstallationOwnershipError(
                "GitHub Installation ownership verification failed"
            ) from None
        finally:
            if self._client is None:
                client.close()

    @staticmethod
    def _validated_login(value: Any) -> str:
        if not isinstance(value, str) or not 1 <= len(value) <= 39:
            raise ValueError("invalid GitHub login")
        if not value[0].isalnum() or not value[-1].isalnum():
            raise ValueError("invalid GitHub login")
        if any(not (char.isalnum() or char == "-") for char in value):
            raise ValueError("invalid GitHub login")
        return value
