"""Token-free mTLS client for the isolated GitHub capability Broker.

Worker and Verifier processes hold only their workload client certificate.
GitHub App signing material and installation tokens remain Broker-side.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_CONTENT_BYTES = 1024 * 1024
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class GitHubCapabilityClientError(RuntimeError):
    """A Broker request failed or returned invalid evidence."""


class GitHubCapabilityBrokerClient:
    """Call task-scoped Broker endpoints using mutual TLS and role proof."""

    def __init__(
        self,
        *,
        base_url: str,
        client_certificate_path: str,
        client_key_path: str,
        ca_bundle_path: str,
        http_client: Any | None = None,
    ) -> None:
        parsed = urlsplit(base_url if isinstance(base_url, str) else "")
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError("Broker URL must be an HTTPS origin")
        paths = (client_certificate_path, client_key_path, ca_bundle_path)
        if any(not isinstance(value, str) or not value.strip() for value in paths):
            raise ValueError("mTLS certificate, key, and CA bundle paths are required")
        self._base_url = base_url.rstrip("/")
        if http_client is None:
            for value in paths:
                path = Path(value)
                if not path.is_file():
                    raise ValueError("mTLS certificate, key, and CA bundle files must exist")
            http_client = httpx.Client(
                cert=(client_certificate_path, client_key_path),
                verify=ca_bundle_path,
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=False,
                trust_env=False,
            )
        self._http = http_client

    @classmethod
    def from_env(cls, *, environ: dict[str, str] | None = None) -> "GitHubCapabilityBrokerClient":
        """Build from file paths supplied by a secret manager or mounted files."""
        env = os.environ if environ is None else environ
        names = {
            "base_url": "JAS_SI_GITHUB_CAPABILITY_BROKER_URL",
            "client_certificate_path": "JAS_SI_GITHUB_CAPABILITY_CLIENT_CERT_PATH",
            "client_key_path": "JAS_SI_GITHUB_CAPABILITY_CLIENT_KEY_PATH",
            "ca_bundle_path": "JAS_SI_GITHUB_CAPABILITY_CA_BUNDLE_PATH",
        }
        values = {key: env.get(name, "") for key, name in names.items()}
        if any(not isinstance(value, str) or not value.strip() for value in values.values()):
            raise ValueError("Broker URL and mTLS file paths are required")
        return cls(**values)

    def close(self) -> None:
        close = getattr(self._http, "close", None)
        if callable(close):
            close()

    @staticmethod
    def _proof(
        *,
        task_id: UUID,
        role: str,
        lease_fence: int | None,
        verifier_claim_token: UUID | None,
    ) -> dict[str, object]:
        if not isinstance(task_id, UUID):
            raise ValueError("Persisted task ID is required")
        if role == "worker":
            if (
                isinstance(lease_fence, bool)
                or not isinstance(lease_fence, int)
                or lease_fence < 1
                or verifier_claim_token is not None
            ):
                raise ValueError("Current worker lease fence is required")
            return {"task_id": str(task_id), "lease_fence": lease_fence}
        if role == "verifier":
            if not isinstance(verifier_claim_token, UUID) or lease_fence is not None:
                raise ValueError("Current verifier claim token is required")
            return {
                "task_id": str(task_id),
                "verifier_claim_token": str(verifier_claim_token),
            }
        raise ValueError("Broker workload role is invalid")

    def _post(self, endpoint: str, payload: dict[str, object]) -> dict[str, Any]:
        try:
            response = self._http.post(
                f"{self._base_url}/internal/github/capabilities/{endpoint}",
                json=payload,
                headers={"Accept": "application/json"},
                timeout=10.0,
            )
            body = response.content
            if len(body) > _MAX_RESPONSE_BYTES:
                raise GitHubCapabilityClientError("Broker response exceeds the configured limit")
            if response.status_code != 200:
                raise GitHubCapabilityClientError("Broker authorization or evidence read failed")
            decoded = json.loads(body)
            if not isinstance(decoded, dict):
                raise GitHubCapabilityClientError("Broker response is invalid")
            return decoded
        except GitHubCapabilityClientError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise GitHubCapabilityClientError("Broker returned invalid JSON") from None
        except Exception:
            # HTTP exceptions may contain private transport or credential data.
            raise GitHubCapabilityClientError("Broker request failed") from None

    def read_commit(
        self,
        *,
        task_id: UUID,
        repository: str,
        commit_sha: str,
        role: str,
        lease_fence: int | None = None,
        verifier_claim_token: UUID | None = None,
    ) -> dict[str, str]:
        proof = self._proof(
            task_id=task_id, role=role, lease_fence=lease_fence,
            verifier_claim_token=verifier_claim_token,
        )
        if not isinstance(repository, str) or not repository.strip() or not _SHA_RE.fullmatch(commit_sha or ""):
            raise ValueError("Repository and immutable commit SHA are required")
        result = self._post("commit", {
            **proof, "repository": repository, "commit_sha": commit_sha,
        })
        tree_sha = result.get("tree_sha")
        if (
            result.get("repository", "").casefold() != repository.casefold()
            or result.get("commit_sha") != commit_sha
            or not isinstance(tree_sha, str)
            or not _SHA_RE.fullmatch(tree_sha)
        ):
            raise GitHubCapabilityClientError("Broker commit metadata does not match the requested task")
        return {"repository": repository, "commit_sha": commit_sha, "tree_sha": tree_sha}

    def read_file(
        self,
        *,
        task_id: UUID,
        repository: str,
        commit_sha: str,
        path: str,
        role: str,
        lease_fence: int | None = None,
        verifier_claim_token: UUID | None = None,
    ) -> dict[str, object]:
        proof = self._proof(
            task_id=task_id, role=role, lease_fence=lease_fence,
            verifier_claim_token=verifier_claim_token,
        )
        if (
            not isinstance(repository, str) or not repository.strip()
            or not isinstance(commit_sha, str) or not _SHA_RE.fullmatch(commit_sha)
            or not isinstance(path, str) or not path.strip()
            or path.startswith("/") or "\\" in path
            or any(part in ("", ".", "..") for part in path.split("/"))
        ):
            raise ValueError("Repository, immutable commit SHA, and safe file path are required")
        result = self._post("read", {
            **proof, "repository": repository, "commit_sha": commit_sha, "path": path,
        })
        if (
            result.get("repository", "").casefold() != repository.casefold()
            or result.get("commit_sha") != commit_sha
            or result.get("path") != path
        ):
            raise GitHubCapabilityClientError("Broker file response does not match the requested task")
        encoded = result.get("content_base64")
        blob_sha = result.get("blob_sha")
        if not isinstance(encoded, str) or not isinstance(blob_sha, str) or not _SHA_RE.fullmatch(blob_sha):
            raise GitHubCapabilityClientError("Broker file integrity metadata is invalid")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise GitHubCapabilityClientError("Broker file content encoding is invalid") from None
        if len(content) > _MAX_CONTENT_BYTES or result.get("content_bytes") != len(content):
            raise GitHubCapabilityClientError("Broker file content length is invalid")
        local_blob_sha = hashlib.sha1(
            b"blob " + str(len(content)).encode("ascii") + b"\0" + content
        ).hexdigest()
        if local_blob_sha != blob_sha:
            raise GitHubCapabilityClientError("Independent Git blob integrity check failed")
        return {
            "repository": repository,
            "commit_sha": commit_sha,
            "path": path,
            "blob_sha": local_blob_sha,
            "content": content,
            "sha256": hashlib.sha256(content).hexdigest(),
        }


__all__ = ["GitHubCapabilityBrokerClient", "GitHubCapabilityClientError"]
