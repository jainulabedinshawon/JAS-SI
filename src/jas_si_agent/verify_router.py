
from __future__ import annotations

import base64
import hashlib
import os
import re

from pathlib import PurePosixPath
from typing import List

import httpx

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field


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
_TIMEOUT_SECONDS = 10.0


class GitHubEvidenceRequest(BaseModel):
    repository: str = Field(min_length=3, max_length=200)
    commit_sha: str = Field(min_length=40, max_length=40)
    paths: List[str] = Field(min_length=1, max_length=10)


def _validate_request(payload: GitHubEvidenceRequest) -> None:
    if not _REPO_PATTERN.fullmatch(payload.repository):
        raise HTTPException(
            status_code=422,
            detail="Invalid GitHub repository format.",
        )

    if not _SHA_PATTERN.fullmatch(payload.commit_sha):
        raise HTTPException(
            status_code=422,
            detail="A full 40-character commit SHA is required.",
        )

    if len(payload.paths) > _MAX_FILES:
        raise HTTPException(
            status_code=422,
            detail="Maximum 10 evidence files are allowed.",
        )

    if len(set(payload.paths)) != len(payload.paths):
        raise HTTPException(
            status_code=422,
            detail="Duplicate evidence paths are not allowed.",
        )

    for path in payload.paths:
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 500
            or path.startswith("/")
            or "\\" in path
            or "\x00" in path
            or any(part in ("", ".", "..") for part in path.split("/"))
        ):
            raise HTTPException(
                status_code=422,
                detail="Invalid repository file path.",
            )


def _github_headers() -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "JAS-SI-Verify/0.1",
    }

    token = os.getenv("JAS_SI_GITHUB_TOKEN")

    if token:
        headers["Authorization"] = f"Bearer {token}"

    return headers


def _github_get(url: str, *, params: dict | None = None) -> dict:
    try:
        response = httpx.get(
            url,
            headers=_github_headers(),
            params=params,
            timeout=_TIMEOUT_SECONDS,
            follow_redirects=False,
        )

    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="GitHub request timed out.",
        ) from None

    except httpx.RequestError:
        raise HTTPException(
            status_code=502,
            detail="GitHub evidence service is unavailable.",
        ) from None

    if response.status_code == 404:
        raise HTTPException(
            status_code=404,
            detail="GitHub commit or evidence file not found.",
        )

    if response.status_code in (401, 403, 429):
        raise HTTPException(
            status_code=503,
            detail="GitHub API access is unavailable or rate limited.",
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail="Unexpected GitHub API response.",
        )

    try:
        data = response.json()
    except ValueError:
        raise HTTPException(
            status_code=502,
            detail="Invalid GitHub API response.",
        ) from None

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=502,
            detail="Unexpected GitHub response structure.",
        )

    return data


def _git_blob_sha1(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()


@router.post("/github/evidence")
def verify_github_evidence(
    payload: GitHubEvidenceRequest,
) -> dict:
    """
    Read-only GitHub evidence verification.

    Verifies that requested file contents match the GitHub
    Git blob identifiers at an immutable commit SHA.

    Does not establish the semantic truth of repository claims.
    """

    _validate_request(payload)

    repository = payload.repository
    commit_sha = payload.commit_sha

    base_url = f"{_GITHUB_API}/repos/{repository}"

    commit_data = _github_get(
        f"{base_url}/commits/{commit_sha}"
    )

    actual_commit_sha = commit_data.get("sha")

    if actual_commit_sha != commit_sha:
        raise HTTPException(
            status_code=502,
            detail="GitHub returned an unexpected commit SHA.",
        )

    commit_object = commit_data.get("commit")

    if not isinstance(commit_object, dict):
        raise HTTPException(
            status_code=502,
            detail="GitHub commit metadata is incomplete.",
        )

    tree = commit_object.get("tree")

    if not isinstance(tree, dict) or not isinstance(tree.get("sha"), str):
        raise HTTPException(
            status_code=502,
            detail="GitHub commit tree metadata is missing.",
        )

    verified_files = []

    for path in payload.paths:
        file_data = _github_get(
            f"{base_url}/contents/{path}",
            params={"ref": commit_sha},
        )

        if file_data.get("type") != "file":
            raise HTTPException(
                status_code=422,
                detail="Requested evidence path is not a file.",
            )

        if file_data.get("encoding") != "base64":
            raise HTTPException(
                status_code=422,
                detail="Unsupported GitHub file encoding.",
            )

        encoded_content = file_data.get("content")

        if not isinstance(encoded_content, str):
            raise HTTPException(
                status_code=502,
                detail="GitHub file content is missing.",
            )

        try:
            content = base64.b64decode(
                encoded_content,
                validate=True,
            )
        except (ValueError, base64.binascii.Error):
            raise HTTPException(
                status_code=502,
                detail="GitHub returned invalid file content.",
            ) from None

        if len(content) > _MAX_FILE_BYTES:
            raise HTTPException(
                status_code=413,
                detail="Evidence file exceeds the size limit.",
            )

        calculated_blob_sha = _git_blob_sha1(content)
        reported_blob_sha = file_data.get("sha")

        if calculated_blob_sha != reported_blob_sha:
            raise HTTPException(
                status_code=422,
                detail="Git blob integrity verification failed.",
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
        "tree_sha": tree["sha"],
        "files_verified": len(verified_files),
        "files": verified_files,
        "read_only": True,
        "semantic_truth_verified": False,
    }
