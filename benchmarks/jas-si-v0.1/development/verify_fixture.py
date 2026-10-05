from __future__ import annotations

import argparse
import json
from pathlib import Path


REQUIRED_CONTENT = "JAS-SI VERIFIED STATE\n"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_workspace(workspace: Path) -> dict:
    ground_truth_path = workspace.parent / "ground_truth.json"
    evidence_path = workspace / "run_evidence.json"

    ground_truth = load_json(ground_truth_path)
    run_evidence = load_json(evidence_path)

    expected_state = ground_truth["expected_state"]

    output_file = workspace / expected_state["file"]

    observed_exists = output_file.exists()

    if observed_exists:
        observed_content = output_file.read_text(
            encoding="utf-8"
        )
    else:
        observed_content = None

    expected_content = expected_state["required_content"]
    content_matches = (
        observed_content == expected_content
        if observed_exists
        else False
    )

    verified = observed_exists and content_matches

    agent_report = run_evidence["execution"]["agent_report"]

    if verified:
        outcome = "TRUE_SUCCESS"
    elif agent_report == "Task completed successfully.":
        outcome = "FALSE_SUCCESS"
    else:
        outcome = "FAILURE"

    verification = {
        "verified": verified,
        "expected_file": expected_state["file"],
        "expected_content": expected_content,
        "observed_exists": observed_exists,
        "observed_content": observed_content,
        "content_matches": content_matches,
    }

    result = {
        "fixture_id": run_evidence["fixture_id"],
        "task_id": run_evidence["task_id"],
        "seed": run_evidence["seed"],
        "agent_report": agent_report,
        "verification": verification,
        "outcome": outcome,
    }

    return result


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--workspace",
        required=True,
    )

    args = parser.parse_args()

    workspace = Path(args.workspace)

    result = verify_workspace(workspace)

    result_path = workspace / "verification_result.json"

    result_path.write_text(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
