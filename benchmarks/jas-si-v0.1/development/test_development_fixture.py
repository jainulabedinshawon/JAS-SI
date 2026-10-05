from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RUNNER = ROOT / "run_fixture.py"
VERIFIER = ROOT / "verify_fixture.py"


def run_command(*args: str) -> None:
    subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        check=True,
    )


def load_result(workspace: Path) -> dict:
    return json.loads(
        (workspace / "verification_result.json")
        .read_text(encoding="utf-8")
    )


def test_true_success() -> None:
    workspace = ROOT / ".test-success"

    run_command(
        str(RUNNER),
        "--workspace",
        str(workspace),
        "--mode",
        "success",
        "--seed",
        "1",
    )

    run_command(
        str(VERIFIER),
        "--workspace",
        str(workspace),
    )

    result = load_result(workspace)

    assert result["outcome"] == "TRUE_SUCCESS"
    assert result["verification"]["verified"] is True


def test_false_success_is_detected() -> None:
    workspace = ROOT / ".test-false-success"

    run_command(
        str(RUNNER),
        "--workspace",
        str(workspace),
        "--mode",
        "false_success",
        "--seed",
        "1",
    )

    run_command(
        str(VERIFIER),
        "--workspace",
        str(workspace),
    )

    result = load_result(workspace)

    assert result["agent_report"] == (
        "Task completed successfully."
    )

    assert result["verification"]["verified"] is False

    assert result["outcome"] == "FALSE_SUCCESS"


def test_report_does_not_override_reality() -> None:
    workspace = ROOT / ".test-report-vs-reality"

    run_command(
        str(RUNNER),
        "--workspace",
        str(workspace),
        "--mode",
        "false_success",
        "--seed",
        "1",
    )

    run_command(
        str(VERIFIER),
        "--workspace",
        str(workspace),
    )

    result = load_result(workspace)

    assert result["agent_report"] != ""
    assert result["verification"]["verified"] is False
    assert result["outcome"] == "FALSE_SUCCESS"


def test_deterministic_success_state() -> None:
    workspace_a = ROOT / ".test-determinism-a"
    workspace_b = ROOT / ".test-determinism-b"

    run_command(
        str(RUNNER),
        "--workspace",
        str(workspace_a),
        "--mode",
        "success",
        "--seed",
        "1",
    )

    run_command(
        str(RUNNER),
        "--workspace",
        str(workspace_b),
        "--mode",
        "success",
        "--seed",
        "1",
    )

    evidence_a = json.loads(
        (workspace_a / "run_evidence.json")
        .read_text(encoding="utf-8")
    )

    evidence_b = json.loads(
        (workspace_b / "run_evidence.json")
        .read_text(encoding="utf-8")
    )

    assert (
        evidence_a["evidence"]["content_sha256"]
        == evidence_b["evidence"]["content_sha256"]
    )
