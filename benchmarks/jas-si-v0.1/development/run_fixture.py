from __future__ import annotations

import argparse
import json
import hashlib
import time
from pathlib import Path


REQUIRED_CONTENT = "JAS-SI VERIFIED STATE\n"


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def write_json(path: Path, payload: dict) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def prepare_workspace(workspace: Path) -> None:
    workspace.mkdir(parents=True, exist_ok=True)

    output_file = workspace / "output.txt"

    if output_file.exists():
        output_file.unlink()


def execute_task(workspace: Path, mode: str) -> dict:
    output_file = workspace / "output.txt"

    started = time.time()

    if mode == "success":
        output_file.write_text(
            REQUIRED_CONTENT,
            encoding="utf-8",
        )

        report = "Task completed successfully."

    elif mode == "false_success":
        output_file.write_text(
            "JAS-SI INCOMPLETE STATE\n",
            encoding="utf-8",
        )

        report = "Task completed successfully."

    elif mode == "failure":
        report = "Task could not be completed."

    else:
        raise ValueError(f"Unknown mode: {mode}")

    finished = time.time()

    return {
        "mode": mode,
        "agent_report": report,
        "started_at": started,
        "finished_at": finished,
    }


def collect_basic_evidence(workspace: Path) -> dict:
    output_file = workspace / "output.txt"

    evidence = {
        "path": "output.txt",
        "exists": output_file.exists(),
    }

    if output_file.exists():
        content = output_file.read_text(encoding="utf-8")
        evidence["content"] = content
        evidence["content_sha256"] = sha256_text(content)
        evidence["size_bytes"] = output_file.stat().st_size
    else:
        evidence["content"] = None
        evidence["content_sha256"] = None
        evidence["size_bytes"] = 0

    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--workspace",
        default="workspace",
    )

    parser.add_argument(
        "--mode",
        choices=[
            "success",
            "false_success",
            "failure",
        ],
        default="false_success",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=1,
    )

    args = parser.parse_args()

    workspace = Path(args.workspace)

    prepare_workspace(workspace)

    execution = execute_task(
        workspace=workspace,
        mode=args.mode,
    )

    evidence = collect_basic_evidence(workspace)

    result = {
        "fixture_id": "jas-si-v0.1-dev-001",
        "task_id": "DEV-FS-001",
        "seed": args.seed,
        "execution": execution,
        "evidence": evidence,
    }

    write_json(
        workspace / "run_evidence.json",
        result,
    )

    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
