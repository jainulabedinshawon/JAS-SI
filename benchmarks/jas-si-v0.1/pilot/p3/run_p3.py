from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


PILOT_ROOT = Path(__file__).resolve().parent
RESULTS_DIR = PILOT_ROOT.parent / "results"
RESULT_PATH = RESULTS_DIR / "p3_multi_agent_result.json"

FIXTURE_PATH = PILOT_ROOT / "fixtures" / "p3_multi_agent_cases.json"


VALID_CONDITIONS = {
    "SINGLE_AGENT",
    "MULTI_AGENT",
}

VALID_LABELS = {
    "TRUE_SUCCESS",
    "FALSE_SUCCESS",
    "FAILURE",
    "FALSE_FAILURE",
}


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


def validate_cases(cases: Any) -> None:
    if not isinstance(cases, list):
        raise ValueError("P3 fixture must contain a JSON array")

    if not cases:
        raise ValueError("P3 fixture must contain at least one case")

    seen_ids: set[str] = set()

    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Each P3 case must be a JSON object")

        case_id = case.get("case_id")

        if not isinstance(case_id, str) or not case_id:
            raise ValueError("Every P3 case requires a non-empty case_id")

        if case_id in seen_ids:
            raise ValueError(f"Duplicate case_id: {case_id}")

        seen_ids.add(case_id)

        condition = case.get("condition")

        if condition not in VALID_CONDITIONS:
            raise ValueError(
                f"{case_id}: invalid condition: {condition}"
            )

        for field in (
            "expected_outcome",
            "observed_outcome",
            "reported_status",
        ):
            value = case.get(field)

            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"{case_id}: {field} must be a non-empty string"
                )

        expected_label = case.get("expected_label")

        if expected_label not in VALID_LABELS:
            raise ValueError(
                f"{case_id}: invalid expected_label: {expected_label}"
            )

        for field in (
            "expected_verified",
            "expected_exact_match",
        ):
            if not isinstance(case.get(field), bool):
                raise ValueError(
                    f"{case_id}: {field} must be boolean"
                )


def verify_case(case: dict, verifier) -> dict:
    verification = verifier.verify(
        expected_outcome=case["expected_outcome"],
        observed_outcome=case["observed_outcome"],
        reported_status=case["reported_status"],
    )

    checks = {
        "label_match": (
            verification.outcome_label
            == case["expected_label"]
        ),
        "verified_match": (
            verification.verified
            == case["expected_verified"]
        ),
        "exact_match": (
            verification.exact_match
            == case["expected_exact_match"]
        ),
        "independence_preserved": (
            verification.independent_of_agent_report is True
        ),
    }

    passed = all(checks.values())

    return {
        "case_id": case["case_id"],
        "condition": case["condition"],
        "expected_outcome": case["expected_outcome"],
        "observed_outcome": case["observed_outcome"],
        "reported_status": case["reported_status"],
        "planner_report": case.get("planner_report"),
        "executor_report": case.get("executor_report"),
        "critic_report": case.get("critic_report"),
        "verification": {
            "verified": verification.verified,
            "verification_basis": verification.verification_basis,
            "independent_of_agent_report": (
                verification.independent_of_agent_report
            ),
            "outcome_label": verification.outcome_label,
            "exact_match": verification.exact_match,
        },
        "expected": {
            "label": case["expected_label"],
            "verified": case["expected_verified"],
            "exact_match": case["expected_exact_match"],
        },
        "checks": checks,
        "passed": passed,
    }


def build_summary(results: list[dict]) -> dict:
    single_agent = [
        item for item in results
        if item["condition"] == "SINGLE_AGENT"
    ]

    multi_agent = [
        item for item in results
        if item["condition"] == "MULTI_AGENT"
    ]

    passed_cases = sum(
        1 for item in results if item["passed"]
    )

    failed_cases = len(results) - passed_cases

    pass_rate = (
        passed_cases / len(results)
        if results
        else 0.0
    )

    return {
        "schema_version": "0.1.0",
        "condition": "P3_MULTI_AGENT_VERIFICATION_CONTROL",
        "case_count": len(results),
        "single_agent_case_count": len(single_agent),
        "multi_agent_case_count": len(multi_agent),
        "passed_cases": passed_cases,
        "failed_cases": failed_cases,
        "pass_rate": pass_rate,
        "all_cases_passed": failed_cases == 0,
        "verification_invariant": (
            "expected_outcome_vs_observed_outcome"
        ),
        "agent_report_is_not_ground_truth": True,
        "results": results,
    }


def main() -> int:
    verifier_module = load_module(
        "jas_si_p3_oracle_verifier",
        PILOT_ROOT.parent / "verifier" / "oracle_verifier.py",
    )

    cases = load_json(FIXTURE_PATH)
    validate_cases(cases)

    verifier = verifier_module.IndependentVerifier()

    results = [
        verify_case(case, verifier)
        for case in cases
    ]

    result = build_summary(results)

    if not result["all_cases_passed"]:
        raise RuntimeError(
            "P3 verification control failed"
        )

    if result["pass_rate"] != 1.0:
        raise RuntimeError(
            f"Unexpected P3 pass rate: {result['pass_rate']}"
        )

    if not result["agent_report_is_not_ground_truth"]:
        raise RuntimeError(
            "Agent report must not be treated as ground truth"
        )

    if not result["verification_invariant"] == (
        "expected_outcome_vs_observed_outcome"
    ):
        raise RuntimeError(
            "P3 verification invariant changed unexpectedly"
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

    print("P3 Multi-Agent Verification Control: PASS")
    print(f"Cases: {result['case_count']}")
    print(f"Passed: {result['passed_cases']}")
    print(f"Failed: {result['failed_cases']}")
    print(f"Pass rate: {result['pass_rate']:.6f}")
    print(
        "Verification invariant: "
        "expected_outcome_vs_observed_outcome"
    )
    print(
        "Agent report is ground truth: "
        f"{result['agent_report_is_not_ground_truth'] is False}"
    )
    print(f"Result: {RESULT_PATH}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
