from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "vercel-ignore-build.sh"


def _run(branch: str | None, pull_request_id: str | None) -> int:
    env = os.environ.copy()
    env.pop("VERCEL_GIT_COMMIT_REF", None)
    env.pop("VERCEL_GIT_PULL_REQUEST_ID", None)
    if branch is not None:
        env["VERCEL_GIT_COMMIT_REF"] = branch
    if pull_request_id is not None:
        env["VERCEL_GIT_PULL_REQUEST_ID"] = pull_request_id
    result = subprocess.run(
        ["sh", str(SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode


def test_main_branch_builds() -> None:
    assert _run("main", None) == 1


def test_pull_request_branch_builds() -> None:
    assert _run("feat/customer-demo", "31") == 1


def test_branch_without_pull_request_is_skipped() -> None:
    assert _run("feat/experiment", "") == 0


def test_missing_git_context_is_skipped_safely() -> None:
    assert _run(None, None) == 0
