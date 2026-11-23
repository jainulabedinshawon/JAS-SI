from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re

from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

from fastapi import APIRouter, HTTPException, Request
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
# Bound the decoded HTTP response body before JSON parsing or Base64 decoding.
_MAX_GITHUB_RESPONSE_BYTES = _MAX_ENCODED_BYTES + _MAX_BASE64_WHITESPACE_BYTES + 65_536

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

class GitHubActionsEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository: str = Field(min_length=3, max_length=200)
    commit_sha: str = Field(
        min_length=40,
        max_length=40,
        pattern=r"^[0-9a-f]{40}$",
    )
    required_workflow_paths: list[str] = Field(min_length=1, max_length=20)

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

def _github_headers(*, access_token: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "JAS-SI-Verify/0.1",
    }

    token = access_token if access_token is not None else os.getenv("JAS_SI_GITHUB_TOKEN")

    if token:
        if not isinstance(token, str) or not token or len(token) > 4096:
            raise _client_error(503, "GitHub installation credential is invalid.")
        headers["Authorization"] = f"Bearer {token}"

    return headers

def _github_get(
    url: str,
    *,
    params: dict[str, str] | None = None,
    access_token: str | None = None,
) -> dict[str, Any]:
    try:
        with httpx.stream(
            "GET",
            url,
            headers=_github_headers(access_token=access_token),
            params=params,
            timeout=_TIMEOUT_SECONDS,
            follow_redirects=False,
        ) as response:
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

            body = bytearray()
            for chunk in response.iter_bytes():
                if len(body) + len(chunk) > _MAX_GITHUB_RESPONSE_BYTES:
                    raise _client_error(
                        413,
                        "GitHub evidence response exceeds the size limit.",
                    )
                body.extend(chunk)

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

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
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

def _verify_github_evidence(
    payload: GitHubEvidenceRequest,
    *,
    access_token: str | None = None,
    access_mode: str = "public_repository_only",
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
        f"{base_url}/commits/{commit_sha}",
        access_token=access_token,
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
            access_token=access_token,
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
        "access_mode": access_mode,
        "semantic_truth_verified": False,
    }



def _persist_evidence_audit_event(
    request: Request,
    payload: GitHubEvidenceRequest,
    *,
    status_code: int,
    outcome: str,
) -> None:
    """Persist GitHub evidence verification outcome before returning it."""
    store = getattr(request.app.state, "security_event_store", None)
    if store is None:
        raise HTTPException(
            status_code=503,
            detail="Evidence verification could not be securely audited",
        )

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "github_evidence_verification",
        "request_id": getattr(request.state, "request_id", "unknown"),
        "method": request.method,
        "endpoint": request.url.path,
        "status_code": status_code,
        "outcome": outcome,
        "repository": payload.repository,
        "commit_sha": payload.commit_sha,
        "requested_file_count": len(payload.paths),
    }
    for field in ("tenant_id", "api_key_id"):
        value = getattr(request.state, field, None)
        if value is not None:
            event[field] = value

    try:
        store.append(event)
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Evidence verification could not be securely audited",
        ) from None


@router.post("/github/evidence")
def verify_github_evidence(
    payload: GitHubEvidenceRequest,
    request: Request,
) -> dict[str, Any]:
    """Verify immutable GitHub evidence and durably audit the outcome."""
    try:
        result = _verify_github_evidence(payload)
    except HTTPException as exc:
        _persist_evidence_audit_event(
            request,
            payload,
            status_code=exc.status_code,
            outcome="rejected",
        )
        raise

    _persist_evidence_audit_event(
        request,
        payload,
        status_code=200,
        outcome="integrity_verified",
    )
    return result


def _verify_github_actions_evidence(
    payload: GitHubActionsEvidenceRequest,
) -> dict[str, Any]:
    """Collect workflow outcomes directly from GitHub for one immutable commit."""
    if not _REPO_PATTERN.fullmatch(payload.repository):
        raise _client_error(422, "Invalid GitHub repository format.")
    if not _SHA_PATTERN.fullmatch(payload.commit_sha):
        raise _client_error(422, "A full 40-character lowercase commit SHA is required.")
    if len(set(payload.required_workflow_paths)) != len(payload.required_workflow_paths):
        raise _client_error(422, "Duplicate required workflow paths are not allowed.")

    for path in payload.required_workflow_paths:
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 500
            or path.startswith("/")
            or "\\" in path
            or "\x00" in path
            or any(part in ("", ".", "..") for part in path.split("/"))
            or not path.startswith(".github/workflows/")
        ):
            raise _client_error(422, "Invalid GitHub Actions workflow path.")

    result = _github_get(
        f"{_GITHUB_API}/repos/{payload.repository}/actions/runs",
        params={"head_sha": payload.commit_sha, "per_page": "100"},
    )
    total_count = result.get("total_count")
    runs = result.get("workflow_runs")
    if not isinstance(total_count, int) or isinstance(total_count, bool) or total_count < 0:
        raise _client_error(502, "GitHub workflow response has an invalid total count.")
    if not isinstance(runs, list):
        raise _client_error(502, "GitHub workflow response is missing its run list.")
    if total_count > 100:
        return {
            "service": "JAS-SI Verify",
            "status": "INCONCLUSIVE",
            "reason": "WORKFLOW_RESULT_SET_TRUNCATED",
            "repository": payload.repository,
            "commit_sha": payload.commit_sha,
            "evidence_origin": "github_api",
            "workflow_runs_collected": len(runs),
            "semantic_truth_verified": False,
            "action_execution_verified": False,
            "workflow_definition_trust": "NOT_ESTABLISHED",
        }

    latest_by_path: dict[str, dict[str, Any]] = {}
    for run in runs:
        if not isinstance(run, dict):
            raise _client_error(502, "GitHub workflow response contains an invalid run.")
        run_sha = run.get("head_sha")
        if not isinstance(run_sha, str) or not _SHA_PATTERN.fullmatch(run_sha):
            raise _client_error(502, "GitHub returned an invalid workflow commit SHA.")
        if run_sha != payload.commit_sha:
            continue
        path = run.get("path")
        if not isinstance(path, str):
            raise _client_error(502, "GitHub returned a workflow run without a path.")
        # GitHub's Actions Runs API returns paths as
        # ".github/workflows/name.yml@refs/heads/branch", not just the
        # repository-relative workflow filename. Compare the filename while
        # retaining exact-commit matching through head_sha above.
        workflow_path, separator, workflow_ref = path.rpartition("@")
        if separator:
            if not workflow_ref:
                raise _client_error(502, "GitHub returned a malformed workflow path.")
            path = workflow_path
        if path not in payload.required_workflow_paths:
            continue
        run_number = run.get("run_number")
        run_attempt = run.get("run_attempt")
        run_id = run.get("id")
        status = run.get("status")
        conclusion = run.get("conclusion")
        if (
            not isinstance(run_number, int) or isinstance(run_number, bool) or run_number < 1
            or not isinstance(run_attempt, int) or isinstance(run_attempt, bool) or run_attempt < 1
            or not isinstance(run_id, int) or isinstance(run_id, bool) or run_id < 1
            or not isinstance(status, str)
            or (conclusion is not None and not isinstance(conclusion, str))
        ):
            raise _client_error(502, "GitHub returned malformed workflow run metadata.")
        previous = latest_by_path.get(path)
        if previous is None or (run_number, run_attempt, run_id) > (
            previous["run_number"], previous["run_attempt"], previous["id"]
        ):
            latest_by_path[path] = {
                "id": run_id,
                "run_number": run_number,
                "run_attempt": run_attempt,
                "status": status,
                "conclusion": conclusion,
                "head_sha": run_sha,
                "path": path,
            }

    collected = []
    overall = "GITHUB_REPORTED_SUCCESS"
    for path in payload.required_workflow_paths:
        run = latest_by_path.get(path)
        if run is None:
            overall = "INCONCLUSIVE" if overall != "GITHUB_REPORTED_FAILURE" else overall
            collected.append({"path": path, "status": "MISSING", "conclusion": None})
            continue
        collected.append(run)
        if run["status"] != "completed":
            if overall != "GITHUB_REPORTED_FAILURE":
                overall = "INCONCLUSIVE"
        elif run["conclusion"] == "success":
            pass
        elif run["conclusion"] in {
            "failure", "cancelled", "timed_out", "action_required", "startup_failure"
        }:
            overall = "GITHUB_REPORTED_FAILURE"
        elif overall != "GITHUB_REPORTED_FAILURE":
            overall = "INCONCLUSIVE"

    return {
        "service": "JAS-SI Verify",
        "status": overall,
        "verification_scope": "github_actions_workflow_outcomes",
        "repository": payload.repository,
        "commit_sha": payload.commit_sha,
        "evidence_origin": "github_api",
        "required_workflows": len(payload.required_workflow_paths),
        "workflow_results": collected,
        "semantic_truth_verified": False,
        "action_execution_verified": False,
        "workflow_definition_trust": "NOT_ESTABLISHED",
        "read_only": True,
    }


def _persist_github_actions_audit_event(
    request: Request,
    payload: GitHubActionsEvidenceRequest,
    *,
    status_code: int,
    outcome: str,
) -> None:
    store = getattr(request.app.state, "security_event_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Evidence verification could not be securely audited")
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "github_actions_evidence_verification",
        "request_id": getattr(request.state, "request_id", "unknown"),
        "method": request.method,
        "endpoint": request.url.path,
        "status_code": status_code,
        "outcome": outcome,
        "repository": payload.repository,
        "commit_sha": payload.commit_sha,
        "required_workflow_count": len(payload.required_workflow_paths),
    }
    for field in ("tenant_id", "api_key_id"):
        value = getattr(request.state, field, None)
        if value is not None:
            event[field] = value
    try:
        store.append(event)
    except Exception:
        raise HTTPException(status_code=503, detail="Evidence verification could not be securely audited") from None


@router.post("/github/actions/evidence")
def verify_github_actions_evidence(
    payload: GitHubActionsEvidenceRequest,
    request: Request,
) -> dict[str, Any]:
    """Collect and verify GitHub Actions outcomes for an exact commit SHA."""
    try:
        result = _verify_github_actions_evidence(payload)
    except HTTPException as exc:
        _persist_github_actions_audit_event(
            request, payload, status_code=exc.status_code, outcome="rejected"
        )
        raise
    _persist_github_actions_audit_event(
        request,
        payload,
        status_code=200,
        outcome=str(result.get("status", "INCONCLUSIVE")).lower(),
    )
    return result
