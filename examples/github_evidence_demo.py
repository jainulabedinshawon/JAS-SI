#!/usr/bin/env python3
"""
Minimal JAS-SI GitHub Evidence Verification API demo.

Usage:
    python examples/github_evidence_demo.py OWNER/REPOSITORY COMMIT_SHA README.md

Environment:
    JAS_SI_API_URL
    JAS_SI_API_KEY

This demo verifies GitHub commit/file integrity only.
It does not establish semantic truth or task completion.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import httpx


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify GitHub evidence using the JAS-SI API."
    )

    parser.add_argument(
        "repository",
        help="GitHub repository in OWNER/REPOSITORY format.",
    )
    parser.add_argument(
        "commit_sha",
        help="Full 40-character lowercase commit SHA.",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="Repository file paths to verify (maximum 10).",
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if len(args.commit_sha) != 40 or any(
        char not in "0123456789abcdef" for char in args.commit_sha
    ):
        raise ValueError(
            "commit_sha must be a full 40-character lowercase SHA."
        )

    if len(args.paths) > 10:
        raise ValueError("A maximum of 10 file paths is supported.")
    if len(set(args.paths)) != len(args.paths):
        raise ValueError("Duplicate file paths are not allowed.")


def build_request(
    repository: str,
    commit_sha: str,
    paths: list[str],
) -> dict[str, Any]:
    return {
        "repository": repository,
        "commit_sha": commit_sha,
        "paths": paths,
    }


def main() -> int:
    args = parse_args()

    try:
        validate_args(args)
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    api_url = os.getenv("JAS_SI_API_URL", "").strip().rstrip("/")
    api_key = os.getenv("JAS_SI_API_KEY", "").strip()

    if not api_url:
        print(
            "Configuration error: JAS_SI_API_URL is not set.",
            file=sys.stderr,
        )
        return 2
    if not api_key:
        print(
            "Configuration error: JAS_SI_API_KEY is not set.",
            file=sys.stderr,
        )
        return 2
    if not api_url.startswith("https://"):
        print(
            "Configuration error: JAS_SI_API_URL must use HTTPS.",
            file=sys.stderr,
        )
        return 2

    endpoint = f"{api_url}/v1/github/evidence"
    payload = build_request(
        repository=args.repository,
        commit_sha=args.commit_sha,
        paths=args.paths,
    )
    headers = {
        "X-API-Key": api_key,
        "Accept": "application/json",
    }

    print("JAS-SI GitHub Evidence Verification")
    print("-----------------------------------")
    print(f"Repository: {args.repository}")
    print(f"Commit: {args.commit_sha}")
    print(f"Files: {len(args.paths)}")
    print("Submitting read-only verification request...\n")

    try:
        response = httpx.post(
            endpoint,
            json=payload,
            headers=headers,
            timeout=30.0,
            follow_redirects=False,
        )
    except httpx.TimeoutException:
        print("Request failed: JAS-SI API timed out.", file=sys.stderr)
        return 1
    except httpx.RequestError:
        print(
            "Request failed: JAS-SI API is unreachable.",
            file=sys.stderr,
        )
        return 1

    try:
        result = response.json()
    except ValueError:
        print(
            f"API returned non-JSON response (HTTP {response.status_code}).",
            file=sys.stderr,
        )
        return 1

    if not isinstance(result, dict):
        print("API returned an unexpected response format.", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))

    if response.status_code != 200:
        print(
            f"\nVerification request failed (HTTP {response.status_code}).",
            file=sys.stderr,
        )
        return 1

    if result.get("status") != "EVIDENCE_INTEGRITY_VERIFIED":
        print(
            "\nUnexpected verification status.",
            file=sys.stderr,
        )
        return 1

    if result.get("semantic_truth_verified") is not False:
        print(
            "\nUnexpected semantic verification flag.",
            file=sys.stderr,
        )
        return 1

    files = result.get("files")
    if not isinstance(files, list) or len(files) != len(args.paths):
        print(
            "\nResponse file count does not match the request.",
            file=sys.stderr,
        )
        return 1

    if any(
        not isinstance(item, dict) or item.get("integrity") != "VERIFIED"
        for item in files
    ):
        print(
            "\nOne or more evidence files were not verified.",
            file=sys.stderr,
        )
        return 1

    print("\nSUCCESS: GitHub evidence integrity verified.")
    print("Scope: immutable commit and file integrity.")
    print("Semantic truth: NOT VERIFIED.")
    print("Repository modifications: NONE.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
