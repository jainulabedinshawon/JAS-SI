from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


PILOT_ROOT = Path(__file__).resolve().parent
RESULTS_DIR = PILOT_ROOT / "results"
RESULT_PATH = RESULTS_DIR / "p1_oracle_result.json"

FIXTURE_PATH = PILOT_ROOT / "fixtures" / "p1_tasks.json"


def load_module(name: str, path: Path):
    if not path.is_file():
        raise FileNotFoundError(f"Module not found: {path}")

    spec = importlib.util.spec_from_file_location(name, path)

    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module specification: {path}")

    module = importlib.util.module_from_spec(spec)

    # Required for Python 3.10 dataclass module resolution
    # when loading modules dynamically from file paths.
    sys.modules[name] = module

    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"JSON file not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_tasks(tasks: Any) -> None:
    if not isinstance(tasks, list):
        raise ValueError("P1 fixture must contain a JSON array")

    if not tasks:
        raise ValueError("P1 fixture must contain at least one task")

    seen_ids: set[str] = set()

    for task in tasks:
        if not isinstance(task, dict):
            raise ValueError("Each task must be a JSON object")

        task_id = task.get("task_id")

        if not isinstance(task_id, str) or not task_id:
            raise ValueError("Every task requires a non-empty task_id")

        if task_id in seen_ids:
            raise ValueError(f"Duplicate task_id: {task_id}")

        seen_ids.add(task_id)

        prompt = task.get("prompt")

        if not isinstance(prompt, str) or not prompt:
            raise ValueError(
                f"Task {task_id}: prompt must be a non-empty string"
            )

        ground_truth = task.get("ground_truth")

        if not isinstance(ground_truth, dict):
            raise ValueError(
                f"Task {task_id}: ground_truth must be an object"
            )

        expected = ground_truth.get("expected_outcome")

        if not isinstance(expected, str) or not expected:
            raise ValueError(
                f"Task {task_id}: expected_outcome must be a non-empty string"
            )


def validate_evidence_record(record: dict) -> None:
    required = {
        "schema_version",
        "task_id",
        "agent_condition",
        "expected_outcome",
        "observed_outcome",
        "agent_report",
        "verification",
        "outcome_label",
        "metrics",
        "timestamp",
    }

    missing = required - set(record)

    if missing:
        raise ValueError(
            f"Evidence record missing fields: {sorted(missing)}"
        )

    if record["outcome_label"] not in {
        "TRUE_SUCCESS",
        "FALSE_SUCCESS",
        "FAILURE",
        "FALSE_FAILURE",
    }:
        raise ValueError(
            f"Invalid outcome label: {record['outcome_label']}"
        )

    agent_report = record["agent_report"]

    if not isinstance(agent_report, dict):
        raise ValueError("agent_report must be an object")

    if not isinstance(agent_report.get("reported_status"), str):
        raise ValueError("reported_status must be a string")

    if not isinstance(agent_report.get("reported_outcome"), str):
        raise ValueError("reported_outcome must be a string")

    verification = record["verification"]

    if not isinstance(verification, dict):
        raise ValueError("verification must be an object")

    if not isinstance(verification.get("verified"), bool):
        raise ValueError("verification.verified must be boolean")

    if not isinstance(
        verification.get("independent_of_agent_report"),
        bool,
    ):
        raise ValueError(
            "verification.independent_of_agent_report must be boolean"
        )

    metrics = record["metrics"]

    if not isinstance(metrics, dict):
        raise ValueError("metrics must be an object")

    if not isinstance(metrics.get("exact_match"), bool):
        raise ValueError("metrics.exact_match must be boolean")


def build_summary(evidence_records: list[dict]) -> dict:
    labels = [
        "TRUE_SUCCESS",
        "FALSE_SUCCESS",
        "FAILURE",
        "FALSE_FAILURE",
    ]

    outcome_counts = {label: 0 for label in labels}

    for record in evidence_records:
        label = record["outcome_label"]
        outcome_counts[label] += 1

    task_count = len(evidence_records)

    true_successes = outcome_counts["TRUE_SUCCESS"]

    accuracy = (
        true_successes / task_count
        if task_count > 0
        else 0.0
    )

    return {
        "schema_version": "0.1.0",
        "condition": "P1_ORACLE",
        "task_count": task_count,
        "outcome_counts": outcome_counts,
        "accuracy": accuracy,
        "evidence_records": evidence_records,
    }


def main() -> int:
    oracle_module = load_module(
        "jas_si_p1_oracle_agent",
        PILOT_ROOT / "agents" / "oracle_agent.py",
    )

    verifier_module = load_module(
        "jas_si_p1_oracle_verifier",
        PILOT_ROOT / "verifier" / "oracle_verifier.py",
    )

    runner_module = load_module(
        "jas_si_p1_pilot_runner",
        PILOT_ROOT / "harness" / "pilot_runner.py",
    )

    tasks = load_json(FIXTURE_PATH)
    validate_tasks(tasks)

    agent = oracle_module.OracleAgent()
    verifier = verifier_module.IndependentVerifier()
    runner = runner_module.PilotRunner(agent, verifier)

    evidence_records = runner.run(tasks)

    if len(evidence_records) != len(tasks):
        raise RuntimeError(
            "Evidence record count does not match task count"
        )

    for record in evidence_records:
        validate_evidence_record(record)

    result = build_summary(evidence_records)

    if result["outcome_counts"]["FALSE_SUCCESS"] != 0:
        raise RuntimeError("P1 Oracle produced FALSE_SUCCESS")

    if result["outcome_counts"]["FAILURE"] != 0:
        raise RuntimeError("P1 Oracle produced FAILURE")

    if result["outcome_counts"]["FALSE_FAILURE"] != 0:
        raise RuntimeError("P1 Oracle produced FALSE_FAILURE")

    if result["outcome_counts"]["TRUE_SUCCESS"] != len(tasks):
        raise RuntimeError(
            "Not all P1 Oracle tasks were TRUE_SUCCESS"
        )

    if result["accuracy"] != 1.0:
        raise RuntimeError(
            f"Unexpected P1 accuracy: {result['accuracy']}"
        )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    with RESULT_PATH.open("w", encoding="utf-8") as handle:
        json.dump(
            result,
            handle,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        handle.write("\n")

    print("P1 Oracle apparatus: PASS")
    print(f"Tasks: {result['task_count']}")
    print(f"Outcome counts: {result['outcome_counts']}")
    print(f"Accuracy: {result['accuracy']:.6f}")
    print(f"Result: {RESULT_PATH}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
