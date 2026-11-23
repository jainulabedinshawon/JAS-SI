"""Broker-owned, task-scoped GitHub content reads.

The installation token is created and consumed inside this module. Callers
receive bounded file content and integrity metadata, never credential material.
"""
from __future__ import annotations

import base64
import binascii
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from jas_si_agent.github_capability_broker import (
    GitHubCapabilityBrokerError,
    ResolvedGitHubTaskCapability,
)
from jas_si_agent.github_app_tokens import GitHubAppTokenError

_MAX_CONTENT_BYTES = 1024 * 1024
_GITHUB_API = "https://api.github.com"
_API_VERSION = "2022-11-28"


class GitHubInstallationTokenIssuer(Protocol):
    def issue(self, *, installation_id: int, repository: str) -> Any: ...


class GitHubCapabilityReadProxy:
    """Enforce persisted task scope, mint a token, and read one exact file."""

    def __init__(
        self,
        token_issuer: GitHubInstallationTokenIssuer,
        *,
        http_client: httpx.Client,
        max_content_bytes: int = _MAX_CONTENT_BYTES,
    ) -> None:
        if token_issuer is None or not callable(getattr(token_issuer, "issue", None)):
            raise ValueError("A trusted GitHub installation token issuer is required")
        if http_client is None or not callable(getattr(http_client, "get", None)):
            raise ValueError("A trusted HTTP client is required")
        if (
            isinstance(max_content_bytes, bool)
            or not isinstance(max_content_bytes, int)
            or not 1 <= max_content_bytes <= _MAX_CONTENT_BYTES
        ):
            raise ValueError("GitHub content size limit is invalid")
        self._token_issuer = token_issuer
        self._http = http_client
        self._max_content_bytes = max_content_bytes

    def read_file(
        self,
        *,
        capability: ResolvedGitHubTaskCapability,
        repository: str,
        commit_sha: str,
        path: str,
    ) -> dict[str, object]:
        if not isinstance(capability, ResolvedGitHubTaskCapability):
            raise GitHubCapabilityBrokerError("Persisted task capability is required")
        capability.authorize_read(
            repository=repository,
            commit_sha=commit_sha,
            path=path,
        )
        try:
            token = self._token_issuer.issue(
                installation_id=capability.installation_id,
                repository=capability.repository_full_name,
            )
            if (
                getattr(token, "installation_id", None) != capability.installation_id
                or getattr(token, "repository", "").casefold()
                != capability.repository_full_name.casefold()
                or not isinstance(getattr(token, "access_token", None), str)
                or not token.access_token
            ):
                raise GitHubCapabilityBrokerError("GitHub token scope does not match task capability")
            encoded_path = "/".join(quote(part, safe="") for part in path.split("/"))
            url = (
                f"{_GITHUB_API}/repos/{capability.repository_full_name}"
                f"/contents/{encoded_path}"
            )
            response = self._http.get(
                url,
                params={"ref": capability.commit_sha},
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token.access_token}",
                    "X-GitHub-Api-Version": _API_VERSION,
                },
                timeout=10.0,
            )
            if response.status_code != 200:
                raise GitHubCapabilityBrokerError("GitHub repository content read failed")
            payload = response.json()
            if (
                not isinstance(payload, dict)
                or payload.get("type") != "file"
                or payload.get("path") != path
                or payload.get("encoding") != "base64"
                or not isinstance(payload.get("content"), str)
            ):
                raise GitHubCapabilityBrokerError("GitHub returned an invalid content response")
            try:
                content = base64.b64decode(payload["content"], validate=True)
            except (ValueError, binascii.Error):
                raise GitHubCapabilityBrokerError("GitHub returned invalid file encoding") from None
            if len(content) > self._max_content_bytes:
                raise GitHubCapabilityBrokerError("GitHub file exceeds the configured read limit")
            blob_sha = payload.get("sha")
            if not isinstance(blob_sha, str) or len(blob_sha) != 40:
                raise GitHubCapabilityBrokerError("GitHub returned invalid file integrity metadata")
            return {
                "repository": capability.repository_full_name,
                "commit_sha": capability.commit_sha,
                "path": path,
                "blob_sha": blob_sha,
                "content_base64": base64.b64encode(content).decode("ascii"),
                "content_bytes": len(content),
            }
        except GitHubCapabilityBrokerError:
            raise
        except GitHubAppTokenError:
            raise GitHubCapabilityBrokerError("GitHub token issuance failed") from None
        except Exception:
            # Never expose HTTP exceptions: they can contain Authorization headers.
            raise GitHubCapabilityBrokerError("GitHub repository content read failed") from None
