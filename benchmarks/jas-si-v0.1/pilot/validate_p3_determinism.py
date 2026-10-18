
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


PILOT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PILOT_ROOT))

import run_p1  # noqa: E402


def run_once() -> dict[str, Any]:
    """Run the existing deterministic P1 Oracle apparatus once."""
    oracle_module = run_p1.load_module(
        "jas_si_p3_oracle_agent",
        PILOT_ROOT / "agents" / "oracle_agent.py",
    )
    verifier_module = run_p1.load_module(
        "jas_si_p3_oracle_verifier",
        PILOT_ROOT / "verifier" / "oracle_verifier.py",
    )
    runner_module = run_p1.load_module(
        "jas_si_p3_pilot_runner",
        PILOT_ROOT / "harness" / "pilot_runner.py",
    )

    tasks = run_p1.load_json(PILOT_ROOT / "fixtures" / "p1_tasks.json")
    run_p1.validate_tasks(tasks)

    runner = runner_module.PilotRunner(
        oracle_module.OracleAgent(),
        verifier_module.IndependentVerifier(),
    )
    records = runner.run(tasks)

    if len(records) != len(tasks):
        raise RuntimeError("Evidence record count does not match task count")

    for record in records:
        run_p1.validate_evidence_record(record)

    summary = run_p1.build_summary(records)

    if summary["task_count"] != len(tasks):
        raise RuntimeError("Unexpected task count")

    if summary["outcome_counts"]["TRUE_SUCCESS"] != len(tasks):
        raise RuntimeError("P3 expected all Oracle tasks to be TRUE_SUCCESS")

    if summary["outcome_counts"]["FALSE_SUCCESS"] != 0:
        raise RuntimeError("P3 detected an unexpected FALSE_SUCCESS")

    if summary["accuracy"] != 1.0:
        raise RuntimeError("P3 expected Oracle accuracy to equal 1.0")

    return summary


def without_runtime_timestamps(value: Any) -> Any:
    """Remove runtime timestamps while preserving all other result fields."""
    if isinstance(value, dict):
        return {
            key: without_runtime_timestamps(item)
            for key, item in value.items()
            if key != "timestamp"
        }

    if isinstance(value, list):
        return [without_runtime_timestamps(item) for item in value]

    return value


def validate_determinism() -> dict[str, Any]:
    first = run_once()
    second = run_once()

    first_stable = without_runtime_timestamps(first)
    second_stable = without_runtime_timestamps(second)

    first_task_ids = [
        record["task_id"] for record in first["evidence_records"]
    ]
    second_task_ids = [
        record["task_id"] for record in second["evidence_records"]
    ]

    stable_fields_match = (
        json.dumps(first_stable, sort_keys=True, separators=(",", ":"))
        == json.dumps(second_stable, sort_keys=True, separators=(",", ":"))
    )
    task_order_match = first_task_ids == second_task_ids
    aggregate_metrics_match = (
        first["task_count"] == second["task_count"]
        and first["outcome_counts"] == second["outcome_counts"]
        and first["accuracy"] == second["accuracy"]
    )

    report = {
        "check": "P3_DETERMINISM_PILOT",
        "status": "PASS" if (
            stable_fields_match
            and task_order_match
            and aggregate_metrics_match
        ) else "FAIL",
        "runs_compared": 2,
        "task_count": first["task_count"],
        "stable_fields_match": stable_fields_match,
        "task_order_match": task_order_match,
        "aggregate_metrics_match": aggregate_metrics_match,
        "runtime_timestamps_excluded": True,
    }

    if report["status"] != "PASS":
        raise RuntimeError(
            "P3 determinism check failed: "
            + json.dumps(report, sort_keys=True)
        )

    return report


def main() -> int:
    report = validate_determinism()
    print(json.dumps(report, indent=2, sort_keys=True))
    print("P3 determinism pilot: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
