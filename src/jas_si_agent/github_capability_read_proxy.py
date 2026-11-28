"""Broker-owned, task-scoped GitHub content reads.

The installation token is created and consumed inside this module. Callers
receive bounded file content and integrity metadata, never credential material.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from jas_si_agent.github_capability_broker import (
    GitHubCapabilityBrokerError,
    ResolvedGitHubTaskCapability,
)
from jas_si_agent.github_app_tokens import GitHubAppTokenError

_MAX_CONTENT_BYTES = 1024 * 1024
# Base64 expands a 1 MiB file to ~1.34 MiB; allow bounded JSON metadata.
_MAX_API_RESPONSE_BYTES = 2 * 1024 * 1024
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

    def close(self) -> None:
        """Close the Broker-owned HTTP connection pool during app shutdown."""
        self._http.close()

    def read_commit(
        self,
        *,
        capability: ResolvedGitHubTaskCapability,
        repository: str,
        commit_sha: str,
    ) -> dict[str, object]:
        """Return immutable commit/tree identity without exposing credentials."""
        if not isinstance(capability, ResolvedGitHubTaskCapability):
            raise GitHubCapabilityBrokerError("Persisted task capability is required")
        capability.authorize_commit(repository=repository, commit_sha=commit_sha)
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
            url = f"{_GITHUB_API}/repos/{capability.repository_full_name}/commits/{capability.commit_sha}"
            with self._http.stream(
                "GET",
                url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token.access_token}",
                    "X-GitHub-Api-Version": _API_VERSION,
                },
                timeout=10.0,
            ) as response:
                if response.status_code != 200:
                    raise GitHubCapabilityBrokerError("GitHub commit metadata read failed")
                declared_length = response.headers.get("content-length")
                if declared_length is not None:
                    try:
                        if int(declared_length) > _MAX_API_RESPONSE_BYTES:
                            raise GitHubCapabilityBrokerError("GitHub API response exceeds the configured read limit")
                    except ValueError:
                        raise GitHubCapabilityBrokerError("GitHub API response length is invalid") from None
                chunks = []
                size = 0
                for chunk in response.iter_bytes(chunk_size=64 * 1024):
                    size += len(chunk)
                    if size > _MAX_API_RESPONSE_BYTES:
                        raise GitHubCapabilityBrokerError("GitHub API response exceeds the configured read limit")
                    chunks.append(chunk)
                try:
                    payload = json.loads(b"".join(chunks))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise GitHubCapabilityBrokerError("GitHub returned invalid commit metadata") from None
            commit = payload.get("sha") if isinstance(payload, dict) else None
            commit_data = payload.get("commit") if isinstance(payload, dict) else None
            tree = commit_data.get("tree") if isinstance(commit_data, dict) else None
            tree_sha = tree.get("sha") if isinstance(tree, dict) else None
            if (
                commit != capability.commit_sha
                or not isinstance(tree_sha, str)
                or len(tree_sha) != 40
                or any(char not in "0123456789abcdef" for char in tree_sha)
            ):
                raise GitHubCapabilityBrokerError("GitHub commit metadata does not match the task")
            return {
                "repository": capability.repository_full_name,
                "commit_sha": capability.commit_sha,
                "tree_sha": tree_sha,
            }
        except GitHubCapabilityBrokerError:
            raise
        except GitHubAppTokenError:
            raise GitHubCapabilityBrokerError("GitHub token issuance failed") from None
        except Exception:
            raise GitHubCapabilityBrokerError("GitHub commit metadata read failed") from None

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
            with self._http.stream(
                "GET",
                url,
                params={"ref": capability.commit_sha},
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token.access_token}",
                    "X-GitHub-Api-Version": _API_VERSION,
                },
                timeout=10.0,
            ) as response:
                if response.status_code != 200:
                    raise GitHubCapabilityBrokerError("GitHub repository content read failed")
                declared_length = response.headers.get("content-length")
                if declared_length is not None:
                    try:
                        if int(declared_length) > _MAX_API_RESPONSE_BYTES:
                            raise GitHubCapabilityBrokerError(
                                "GitHub API response exceeds the configured read limit"
                            )
                    except ValueError:
                        raise GitHubCapabilityBrokerError(
                            "GitHub API response length is invalid"
                        ) from None
                response_chunks = []
                response_size = 0
                for chunk in response.iter_bytes(chunk_size=64 * 1024):
                    response_size += len(chunk)
                    if response_size > _MAX_API_RESPONSE_BYTES:
                        raise GitHubCapabilityBrokerError(
                            "GitHub API response exceeds the configured read limit"
                        )
                    response_chunks.append(chunk)
                try:
                    payload = json.loads(b"".join(response_chunks))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise GitHubCapabilityBrokerError(
                        "GitHub returned an invalid content response"
                    ) from None
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
            if (
                not isinstance(blob_sha, str)
                or len(blob_sha) != 40
                or any(char not in "0123456789abcdef" for char in blob_sha)
            ):
                raise GitHubCapabilityBrokerError("GitHub returned invalid file integrity metadata")
            # Recompute Git's canonical blob object ID from the exact bytes.
            # A shape-valid SHA alone is not independent content-integrity evidence.
            git_blob_header = f"blob {len(content)}\\0".encode("ascii")
            computed_blob_sha = hashlib.sha1(git_blob_header + content).hexdigest()
            if computed_blob_sha != blob_sha:
                raise GitHubCapabilityBrokerError("GitHub file content failed blob integrity verification")
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


def build_github_capability_read_proxy(settings: Any) -> GitHubCapabilityReadProxy:
    """Build a Broker-local proxy from dedicated, non-public runtime settings."""
    app_id = getattr(settings, "github_capability_app_id", None)
    private_key_path = getattr(settings, "github_capability_app_private_key_path", None)
    private_key_pem = getattr(settings, "github_capability_app_private_key_pem", None)
    if (
        isinstance(app_id, bool) or not isinstance(app_id, int) or app_id <= 0
        or ((private_key_path is None) == (private_key_pem is None))
        or (private_key_path is not None and (not isinstance(private_key_path, str) or not private_key_path.strip()))
        or (private_key_pem is not None and not isinstance(private_key_pem, bytes))
    ):
        raise ValueError("Dedicated GitHub Capability App credentials are not configured")
    from jas_si_agent.github_app_tokens import (
        GitHubAppInstallationTokenIssuer,
        GitHubAppTokenSettings,
    )

    issuer = GitHubAppInstallationTokenIssuer(
        GitHubAppTokenSettings(
            app_id=app_id,
            private_key_path=private_key_path,
            private_key_pem=private_key_pem,
        )
    )
    client = httpx.Client(
        timeout=httpx.Timeout(10.0, connect=5.0),
        follow_redirects=False,
        trust_env=False,
    )
    return GitHubCapabilityReadProxy(issuer, http_client=client)

