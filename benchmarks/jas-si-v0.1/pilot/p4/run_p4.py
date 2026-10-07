from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


PILOT_ROOT = Path(__file__).resolve().parent
RESULTS_DIR = PILOT_ROOT.parent / "results"
RESULT_PATH = RESULTS_DIR / "p4_determinism_result.json"

FIXTURE_PATH = PILOT_ROOT / "fixtures" / "p4_determinism_cases.json"


def load_module(name: str, path: Path):
    if not path.is_file():
        raise FileNotFoundError(f"Module not found: {path}")

    spec = importlib.util.spec_from_file_location(name, path)

    if spec is None or spec.loader is None:
        raise ImportError(
            f"Unable to load module specification: {path}"
        )

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
        raise ValueError("P4 fixture must contain a JSON array")

    if not cases:
        raise ValueError("P4 fixture must not be empty")

    seen_ids: set[str] = set()

    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Each P4 case must be a JSON object")

        case_id = case.get("case_id")

        if not isinstance(case_id, str) or not case_id:
            raise ValueError(
                "Every P4 case requires a non-empty case_id"
            )

        if case_id in seen_ids:
            raise ValueError(
                f"Duplicate case_id: {case_id}"
            )

        seen_ids.add(case_id)

        for field in (
            "expected_outcome",
            "observed_outcome",
            "reported_status",
            "expected_label",
        ):
            value = case.get(field)

            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"{case_id}: {field} must be a non-empty string"
                )

        for field in (
            "expected_verified",
            "expected_exact_match",
        ):
            if not isinstance(case.get(field), bool):
                raise ValueError(
                    f"{case_id}: {field} must be boolean"
                )

        repetitions = case.get("repetitions", 1)

        if not isinstance(repetitions, int):
            raise ValueError(
                f"{case_id}: repetitions must be an integer"
            )

        if repetitions < 1:
            raise ValueError(
                f"{case_id}: repetitions must be >= 1"
            )


def verification_snapshot(result) -> dict:
    return {
        "verified": result.verified,
        "exact_match": result.exact_match,
        "verification_basis": result.verification_basis,
        "outcome_label": result.outcome_label,
        "independent_of_agent_report": (
            result.independent_of_agent_report
        ),
    }


def run_case(case: dict, verifier) -> dict:
    repetitions = case.get("repetitions", 1)

    snapshots = []

    for _ in range(repetitions):
        result = verifier.verify(
            expected_outcome=case["expected_outcome"],
            observed_outcome=case["observed_outcome"],
            reported_status=case["reported_status"],
        )

        snapshots.append(
            verification_snapshot(result)
        )

    first = snapshots[0]

    deterministic = all(
        snapshot == first
        for snapshot in snapshots
    )

    expected_match = (
        first["verified"]
        == case["expected_verified"]
    )

    exact_match = (
        first["exact_match"]
        == case["expected_exact_match"]
    )

    label_match = (
        first["outcome_label"]
        == case["expected_label"]
    )

    independence_flag = (
        first["independent_of_agent_report"] is True
    )

    passed = all(
        (
            deterministic,
            expected_match,
            exact_match,
            label_match,
            independence_flag,
        )
    )

    return {
        "case_id": case["case_id"],
        "repetitions": repetitions,
        "input": {
            "expected_outcome": case["expected_outcome"],
            "observed_outcome": case["observed_outcome"],
            "reported_status": case["reported_status"],
        },
        "expected": {
            "verified": case["expected_verified"],
            "exact_match": case["expected_exact_match"],
            "outcome_label": case["expected_label"],
        },
        "snapshots": snapshots,
        "checks": {
            "deterministic": deterministic,
            "verified_match": expected_match,
            "exact_match": exact_match,
            "label_match": label_match,
            "independence_flag": independence_flag,
        },
        "passed": passed,
    }


def run_report_invariance_control(verifier) -> dict:
    scenarios = [
        {
            "scenario_id": "P4-RI-CORRECT",
            "expected_outcome": "EXPECTED",
            "observed_outcome": "EXPECTED",
            "reports": ["SUCCESS", "FAILURE"],
        },
        {
            "scenario_id": "P4-RI-WRONG",
            "expected_outcome": "EXPECTED",
            "observed_outcome": "WRONG",
            "reports": ["SUCCESS", "FAILURE"],
        },
    ]

    results = []

    for scenario in scenarios:
        snapshots = []

        for report in scenario["reports"]:
            result = verifier.verify(
                expected_outcome=scenario["expected_outcome"],
                observed_outcome=scenario["observed_outcome"],
                reported_status=report,
            )

            snapshots.append(
                {
                    "reported_status": report,
                    "verified": result.verified,
                    "exact_match": result.exact_match,
                    "verification_basis": (
                        result.verification_basis
                    ),
                    "outcome_label": result.outcome_label,
                }
            )

        core_values = [
            (
                item["verified"],
                item["exact_match"],
                item["verification_basis"],
            )
            for item in snapshots
        ]

        core_invariant = (
            len(set(core_values)) == 1
        )

        results.append(
            {
                "scenario_id": scenario["scenario_id"],
                "snapshots": snapshots,
                "core_verification_invariant": core_invariant,
            }
        )

    return {
        "results": results,
        "all_core_invariants_hold": all(
            item["core_verification_invariant"]
            for item in results
        ),
    }


def build_summary(
    case_results: list[dict],
    report_invariance: dict,
) -> dict:
    passed_cases = sum(
        1 for item in case_results
        if item["passed"]
    )

    failed_cases = (
        len(case_results) - passed_cases
    )

    pass_rate = (
        passed_cases / len(case_results)
        if case_results
        else 0.0
    )

    return {
        "schema_version": "0.1.0",
        "condition": "P4_DETERMINISM_AND_REPORT_INVARIANCE",
        "case_count": len(case_results),
        "passed_cases": passed_cases,
        "failed_cases": failed_cases,
        "pass_rate": pass_rate,
        "all_cases_passed": failed_cases == 0,
        "report_invariance": report_invariance,
        "core_invariant": (
            "verified_and_exact_match_depend_on_"
            "expected_and_observed_outcomes"
        ),
        "results": case_results,
    }


def main() -> int:
    verifier_module = load_module(
        "jas_si_p4_oracle_verifier",
        PILOT_ROOT.parent / "verifier" / "oracle_verifier.py",
    )

    cases = load_json(FIXTURE_PATH)

    validate_cases(cases)

    verifier = verifier_module.IndependentVerifier()

    case_results = [
        run_case(case, verifier)
        for case in cases
    ]

    report_invariance = run_report_invariance_control(
        verifier
    )

    result = build_summary(
        case_results,
        report_invariance,
    )

    if not result["all_cases_passed"]:
        raise RuntimeError(
            "P4 determinism control failed"
        )

    if result["pass_rate"] != 1.0:
        raise RuntimeError(
            f"Unexpected P4 pass rate: "
            f"{result['pass_rate']}"
        )

    if not report_invariance[
        "all_core_invariants_hold"
    ]:
        raise RuntimeError(
            "P4 report-invariance control failed"
        )

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with RESULT_PATH.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            result,
            handle,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        handle.write("\n")

    print(
        "P4 Determinism and Report-Invariance Control: PASS"
    )
    print(f"Cases: {result['case_count']}")
    print(f"Passed: {result['passed_cases']}")
    print(f"Failed: {result['failed_cases']}")
    print(f"Pass rate: {result['pass_rate']:.6f}")
    print(
        "Core report-invariance: "
        f"{report_invariance['all_core_invariants_hold']}"
    )
    print(f"Result: {RESULT_PATH}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
