from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


P7_ROOT = Path(__file__).resolve().parent
FIXTURE_PATH = P7_ROOT / "fixtures" / "p7_leakage_cases.json"

RESULTS_DIR = P7_ROOT.parents[1] / "results"
RESULT_PATH = RESULTS_DIR / "p7_leakage_check_result.json"


def load_json(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_fixture(fixture: Any) -> None:
    if not isinstance(fixture, dict):
        raise ValueError("P7 fixture must be a JSON object")

    forbidden_keys = fixture.get("forbidden_keys")

    if not isinstance(forbidden_keys, list) or not forbidden_keys:
        raise ValueError("forbidden_keys must be a non-empty list")

    if any(
        not isinstance(key, str) or not key.strip()
        for key in forbidden_keys
    ):
        raise ValueError(
            "Every forbidden key must be a non-empty string"
        )

    if len(set(forbidden_keys)) != len(forbidden_keys):
        raise ValueError("forbidden_keys must not contain duplicates")

    cases = fixture.get("cases")

    if not isinstance(cases, list) or not cases:
        raise ValueError("cases must be a non-empty list")

    seen_case_ids = set()

    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Every P7 case must be an object")

        case_id = case.get("case_id")

        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("Every case requires a non-empty case_id")

        if case_id in seen_case_ids:
            raise ValueError(f"Duplicate case_id: {case_id}")

        seen_case_ids.add(case_id)

        if "agent_payload" not in case:
            raise ValueError(f"{case_id}: agent_payload is required")

        if not isinstance(case["agent_payload"], (dict, list)):
            raise ValueError(
                f"{case_id}: agent_payload must be an object or array"
            )

        if not isinstance(case.get("expected_leakage_detected"), bool):
            raise ValueError(
                f"{case_id}: expected_leakage_detected must be boolean"
            )


def find_forbidden_keys(
    value: Any,
    forbidden_keys: set[str],
    path: str = "$",
) -> list[dict[str, str]]:
    findings = []

    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"

            if key in forbidden_keys:
                findings.append(
                    {
                        "key": key,
                        "path": child_path,
                    }
                )

            findings.extend(
                find_forbidden_keys(
                    child,
                    forbidden_keys,
                    child_path,
                )
            )

    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(
                find_forbidden_keys(
                    child,
                    forbidden_keys,
                    f"{path}[{index}]",
                )
            )

    return findings


def evaluate_case(
    case: dict,
    forbidden_keys: set[str],
) -> dict:
    findings = find_forbidden_keys(
        case["agent_payload"],
        forbidden_keys,
    )

    leakage_detected = bool(findings)
    expected = case["expected_leakage_detected"]

    return {
        "case_id": case["case_id"],
        "expected_leakage_detected": expected,
        "actual_leakage_detected": leakage_detected,
        "expectation_match": leakage_detected == expected,
        "findings": findings,
        "passed": leakage_detected == expected,
    }


def main() -> int:
    fixture = load_json(FIXTURE_PATH)
    validate_fixture(fixture)

    forbidden_keys = set(fixture["forbidden_keys"])

    results = [
        evaluate_case(case, forbidden_keys)
        for case in fixture["cases"]
    ]

    passed_cases = sum(
        1 for result in results if result["passed"]
    )
    failed_cases = len(results) - passed_cases

    detected_cases = sum(
        1
        for result in results
        if result["actual_leakage_detected"]
    )

    clean_cases = len(results) - detected_cases

    summary = {
        "schema_version": "0.1.0",
        "condition": "P7_LEAKAGE_CHECK",
        "case_count": len(results),
        "passed_cases": passed_cases,
        "failed_cases": failed_cases,
        "pass_rate": passed_cases / len(results),
        "all_cases_passed": failed_cases == 0,
        "cases_with_detected_leakage": detected_cases,
        "cases_without_detected_leakage": clean_cases,
        "forbidden_keys": sorted(forbidden_keys),
        "detection_scope": (
            "Structural JSON key-name detection only. "
            "Semantic and other indirect leakage may not be detected."
        ),
        "scope_note": (
            "Development fixtures validate the leakage detector, "
            "not actual agent behavior or complete leakage prevention."
        ),
        "results": results,
    }

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

    print("P7 Leakage Check")
    print(f"Cases: {summary['case_count']}")
    print(f"Passed: {summary['passed_cases']}")
    print(f"Failed: {summary['failed_cases']}")
    print(f"Detected leakage cases: {detected_cases}")
    print(f"Clean cases: {clean_cases}")
    print(f"Pass rate: {summary['pass_rate']:.6f}")
    print(f"Result: {RESULT_PATH}")

    if not summary["all_cases_passed"]:
        print("P7 apparatus validation: FAIL", file=sys.stderr)
        return 1

    print("P7 apparatus validation: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
