from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


P5_ROOT = Path(__file__).resolve().parent
FIXTURE_PATH = P5_ROOT / "fixtures" / "p5_floor_ceiling_cases.json"

RESULTS_DIR = P5_ROOT.parents[1] / "results"
RESULT_PATH = RESULTS_DIR / "p5_floor_ceiling_result.json"

OUTCOME_KEYS = (
    "TRUE_SUCCESS",
    "FALSE_SUCCESS",
    "FAILURE",
    "FALSE_FAILURE",
)

METRIC_NAMES = ("FSR", "RA", "FFR")


def load_json(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_outcomes(outcomes: Any, condition_id: str) -> None:
    if not isinstance(outcomes, dict):
        raise ValueError(
            f"{condition_id}: outcomes must be a JSON object"
        )

    for key in OUTCOME_KEYS:
        value = outcomes.get(key)

        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                f"{condition_id}: {key} must be an integer"
            )

        if value < 0:
            raise ValueError(
                f"{condition_id}: {key} cannot be negative"
            )

    if sum(outcomes.values()) <= 0:
        raise ValueError(
            f"{condition_id}: total outcomes must be positive"
        )


def validate_fixture(cases: Any) -> None:
    if not isinstance(cases, list) or not cases:
        raise ValueError("P5 fixture must be a non-empty JSON array")

    seen_case_ids = set()

    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Every P5 case must be an object")

        case_id = case.get("case_id")

        if not isinstance(case_id, str) or not case_id:
            raise ValueError("Every case requires case_id")

        if case_id in seen_case_ids:
            raise ValueError(f"Duplicate case_id: {case_id}")

        seen_case_ids.add(case_id)

        if not isinstance(case.get("expected_pass"), bool):
            raise ValueError(
                f"{case_id}: expected_pass must be boolean"
            )

        conditions = case.get("conditions")

        if not isinstance(conditions, list) or not conditions:
            raise ValueError(
                f"{case_id}: conditions must be a non-empty list"
            )

        seen_condition_ids = set()

        for condition in conditions:
            if not isinstance(condition, dict):
                raise ValueError(
                    f"{case_id}: each condition must be an object"
                )

            condition_id = condition.get("condition_id")

            if not isinstance(condition_id, str) or not condition_id:
                raise ValueError(
                    f"{case_id}: condition_id is required"
                )

            if condition_id in seen_condition_ids:
                raise ValueError(
                    f"{case_id}: duplicate condition_id {condition_id}"
                )

            seen_condition_ids.add(condition_id)

            if not isinstance(condition.get("scripted_control"), bool):
                raise ValueError(
                    f"{condition_id}: scripted_control must be boolean"
                )

            validate_outcomes(
                condition.get("outcomes"),
                condition_id,
            )


def calculate_metrics(outcomes: dict) -> dict:
    true_success = outcomes["TRUE_SUCCESS"]
    false_success = outcomes["FALSE_SUCCESS"]
    failure = outcomes["FAILURE"]
    false_failure = outcomes["FALSE_FAILURE"]

    total = (
        true_success
        + false_success
        + failure
        + false_failure
    )

    fsr_denominator = true_success + false_success
    ffr_denominator = false_failure + failure

    if fsr_denominator <= 0:
        raise ValueError(
            "FSR denominator is zero: TRUE_SUCCESS + FALSE_SUCCESS"
        )

    if ffr_denominator <= 0:
        raise ValueError(
            "FFR denominator is zero: FALSE_FAILURE + FAILURE"
        )

    return {
        "FSR": false_success / fsr_denominator,
        "RA": (true_success + failure) / total,
        "FFR": false_failure / ffr_denominator,
    }


def is_saturated(values: list[float]) -> bool:
    if not values:
        raise ValueError("Cannot evaluate an empty metric list")

    return all(value == 0.0 for value in values) or all(
        value == 1.0 for value in values
    )


def evaluate_case(case: dict) -> dict:
    included_conditions = []
    excluded_conditions = []

    for condition in case["conditions"]:
        record = {
            "condition_id": condition["condition_id"],
            "scripted_control": condition["scripted_control"],
            "outcomes": condition["outcomes"],
        }

        if condition["scripted_control"]:
            excluded_conditions.append(record)
            continue

        record["metrics"] = calculate_metrics(condition["outcomes"])
        included_conditions.append(record)

    # Two or more non-scripted conditions are required to
    # evaluate cross-condition floor/ceiling discrimination.
    enough_conditions = len(included_conditions) >= 2

    saturation = {}

    for metric_name in METRIC_NAMES:
        values = [
            condition["metrics"][metric_name]
            for condition in included_conditions
        ]

        saturation[metric_name] = {
            "values": values,
            "uniformly_saturated": (
                is_saturated(values) if values else None
            ),
        }

    any_saturated = any(
        item["uniformly_saturated"] is True
        for item in saturation.values()
    )

    passed = enough_conditions and not any_saturated

    return {
        "case_id": case["case_id"],
        "expected_pass": case["expected_pass"],
        "actual_pass": passed,
        "expectation_match": passed == case["expected_pass"],
        "included_condition_count": len(included_conditions),
        "excluded_scripted_control_count": len(excluded_conditions),
        "conditions": included_conditions,
        "excluded_conditions": excluded_conditions,
        "metric_saturation": saturation,
        "passed": passed == case["expected_pass"],
    }


def main() -> int:
    cases = load_json(FIXTURE_PATH)
    validate_fixture(cases)

    results = [evaluate_case(case) for case in cases]

    passed_cases = sum(1 for result in results if result["passed"])
    failed_cases = len(results) - passed_cases
    pass_rate = passed_cases / len(results)

    summary = {
        "schema_version": "0.1.0",
        "condition": "P5_FLOOR_CEILING_CHECK",
        "case_count": len(results),
        "passed_cases": passed_cases,
        "failed_cases": failed_cases,
        "pass_rate": pass_rate,
        "all_cases_passed": failed_cases == 0,
        "metric_definitions": {
            "FSR": "FALSE_SUCCESS / (TRUE_SUCCESS + FALSE_SUCCESS)",
            "RA": "(TRUE_SUCCESS + FAILURE) / total_runs",
            "FFR": "FALSE_FAILURE / (FALSE_FAILURE + FAILURE)",
        },
        "scope_note": (
            "Fixture validates the saturation detector only; "
            "it does not establish actual agent performance."
        ),
        "results": results,
    }

    if not summary["all_cases_passed"]:
        raise RuntimeError("P5 apparatus fixture validation failed")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    with RESULT_PATH.open("w", encoding="utf-8") as handle:
        json.dump(
            summary,
            handle,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        handle.write("\n")

    print("P5 Floor/Ceiling Check: PASS")
    print(f"Cases: {summary['case_count']}")
    print(f"Passed: {summary['passed_cases']}")
    print(f"Failed: {summary['failed_cases']}")
    print(f"Pass rate: {summary['pass_rate']:.6f}")
    print(f"Result: {RESULT_PATH}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
