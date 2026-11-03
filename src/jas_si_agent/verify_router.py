from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re

from typing import Any
from urllib.parse import quote

import httpx

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(
    prefix="/v1",
    tags=["GitHub Evidence Verification"],
)

_GITHUB_API = "https://api.github.com"

_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_REPO_PATTERN = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
)

_MAX_FILES = 10
_MAX_FILE_BYTES = 1_000_000
_MAX_ENCODED_BYTES = ((_MAX_FILE_BYTES + 2) // 3) * 4

# Permit normal GitHub Base64 line wrapping, but bound whitespace too.
_MAX_BASE64_WHITESPACE_BYTES = 16_384

_TIMEOUT_SECONDS = 10.0

class GitHubEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository: str = Field(min_length=3, max_length=200)
    commit_sha: str = Field(
        min_length=40,
        max_length=40,
        pattern=r"^[0-9a-f]{40}$",
    )
    paths: list[str] = Field(min_length=1, max_length=_MAX_FILES)

def _client_error(status_code: int, detail: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail=detail,
    )

def _validate_request(payload: GitHubEvidenceRequest) -> None:
    if not _REPO_PATTERN.fullmatch(payload.repository):
        raise _client_error(
            422,
            "Invalid GitHub repository format.",
        )

    if not _SHA_PATTERN.fullmatch(payload.commit_sha):
        raise _client_error(
            422,
            "A full 40-character lowercase commit SHA is required.",
        )

    if not payload.paths or len(payload.paths) > _MAX_FILES:
        raise _client_error(
            422,
            "Between 1 and 10 evidence files are required.",
        )

    if len(set(payload.paths)) != len(payload.paths):
        raise _client_error(
            422,
            "Duplicate evidence paths are not allowed.",
        )

    for path in payload.paths:
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 500
            or path.startswith("/")
            or "\\" in path
            or "\x00" in path
            or any(
                part in ("", ".", "..")
                for part in path.split("/")
            )
        ):
            raise _client_error(
                422,
                "Invalid repository file path.",
            )

def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "JAS-SI-Verify/0.1",
    }

    token = os.getenv("JAS_SI_GITHUB_TOKEN")

    if token:
        headers["Authorization"] = f"Bearer {token}"

    return headers

def _github_get(
    url: str,
    *,
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    try:
        response = httpx.get(
            url,
            headers=_github_headers(),
            params=params,
            timeout=_TIMEOUT_SECONDS,
            follow_redirects=False,
        )

    except httpx.TimeoutException:
        raise _client_error(
            504,
            "GitHub request timed out.",
        ) from None

    except httpx.RequestError:
        raise _client_error(
            502,
            "GitHub evidence service is unavailable.",
        ) from None

    if response.status_code == 404:
        raise _client_error(
            404,
            "GitHub commit or evidence file not found.",
        )

    if response.status_code in (401, 403, 429):
        raise _client_error(
            503,
            "GitHub API access is unavailable or rate limited.",
        )

    if response.status_code != 200:
        raise _client_error(
            502,
            "Unexpected GitHub API response.",
        )

    try:
        data = response.json()
    except (ValueError, TypeError):
        raise _client_error(
            502,
            "Invalid GitHub API response.",
        ) from None

    if not isinstance(data, dict):
        raise _client_error(
            502,
            "Unexpected GitHub response structure.",
        )

    return data

def _git_blob_sha1(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()

def _decode_github_content(encoded_content: Any) -> bytes:
    """
    Validate and decode GitHub Base64 content.

    The encoded-size and whitespace limits are checked before
    Base64 decoding to prevent oversized decoded allocations.
    """

    if not isinstance(encoded_content, str):
        raise _client_error(
            502,
            "GitHub file content is missing or invalid.",
        )

    # Bound the raw string before regex or Base64 processing.
    if len(encoded_content) > (
        _MAX_ENCODED_BYTES + _MAX_BASE64_WHITESPACE_BYTES
    ):
        raise _client_error(
            413,
            "Evidence file exceeds the size limit.",
        )

    # GitHub may wrap Base64 with ASCII whitespace.
    normalized = re.sub(
        r"[ \t\r\n]",
        "",
        encoded_content,
    )

    if not normalized:
        raise _client_error(
            502,
            "GitHub returned empty file content.",
        )

    if len(normalized) > _MAX_ENCODED_BYTES:
        raise _client_error(
            413,
            "Evidence file exceeds the size limit.",
        )

    # Base64 must consist of complete 4-character groups.
    if len(normalized) % 4 != 0:
        raise _client_error(
            502,
            "GitHub returned invalid Base64 content.",
        )

    padding = len(normalized) - len(normalized.rstrip("="))
    expected_decoded_size = (len(normalized) // 4) * 3 - padding

    if expected_decoded_size > _MAX_FILE_BYTES:
        raise _client_error(
            413,
            "Evidence file exceeds the size limit.",
        )

    try:
        content = base64.b64decode(
            normalized,
            validate=True,
        )
    except (binascii.Error, ValueError, TypeError):
        raise _client_error(
            502,
            "GitHub returned invalid Base64 content.",
        ) from None

    # Exact decoded-size check, including Base64 padding effects.
    if len(content) > _MAX_FILE_BYTES:
        raise _client_error(
            413,
            "Evidence file exceeds the size limit.",
        )

    return content

def _require_sha(value: Any, description: str) -> str:
    if not isinstance(value, str) or not _SHA_PATTERN.fullmatch(value):
        raise _client_error(
            502,
            f"GitHub returned invalid {description}.",
        )

    return value

@router.post("/github/evidence")
def verify_github_evidence(
    payload: GitHubEvidenceRequest,
) -> dict[str, Any]:
    """
    Read-only GitHub evidence integrity verification.

    Confirms that requested file contents match GitHub Git blob
    identifiers at an immutable commit SHA.

    This endpoint does not execute actions, modify repositories,
    or establish the semantic truth of repository claims.
    """

    _validate_request(payload)

    repository = payload.repository
    commit_sha = payload.commit_sha

    base_url = f"{_GITHUB_API}/repos/{repository}"

    commit_data = _github_get(
        f"{base_url}/commits/{commit_sha}"
    )

    actual_commit_sha = _require_sha(
        commit_data.get("sha"),
        "commit SHA",
    )

    if actual_commit_sha != commit_sha:
        raise _client_error(
            502,
            "GitHub returned an unexpected commit SHA.",
        )

    commit_object = commit_data.get("commit")

    if not isinstance(commit_object, dict):
        raise _client_error(
            502,
            "GitHub commit metadata is incomplete.",
        )

    tree = commit_object.get("tree")

    if not isinstance(tree, dict):
        raise _client_error(
            502,
            "GitHub commit tree metadata is missing.",
        )

    tree_sha = _require_sha(
        tree.get("sha"),
        "tree SHA",
    )

    verified_files = []

    for path in payload.paths:
        safe_path_url = (
            f"{base_url}/contents/{quote(path, safe='/')}"
        )

        file_data = _github_get(
            safe_path_url,
            params={"ref": commit_sha},
        )

        if file_data.get("type") != "file":
            raise _client_error(
                422,
                "Requested evidence path is not a file.",
            )

        if file_data.get("encoding") != "base64":
            raise _client_error(
                422,
                "Unsupported GitHub file encoding.",
            )

        content = _decode_github_content(
            file_data.get("content")
        )

        calculated_blob_sha = _git_blob_sha1(content)
        reported_blob_sha = _require_sha(
            file_data.get("sha"),
            "file blob SHA",
        )

        if calculated_blob_sha != reported_blob_sha:
            raise _client_error(
                422,
                "Git blob integrity verification failed.",
            )

        verified_files.append(
            {
                "path": path,
                "blob_sha": calculated_blob_sha,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
                "integrity": "VERIFIED",
            }
        )

    return {
        "service": "JAS-SI Verify",
        "status": "EVIDENCE_INTEGRITY_VERIFIED",
        "verification_scope": "github_commit_and_file_integrity",
        "repository": repository,
        "commit_sha": actual_commit_sha,
        "tree_sha": tree_sha,
        "files_verified": len(verified_files),
        "files": verified_files,
        "read_only": True,
        "semantic_truth_verified": False,
    }
