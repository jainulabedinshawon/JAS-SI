from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


PILOT_ROOT = Path(__file__).resolve().parents[1]
P2_ROOT = Path(__file__).resolve().parent

FIXTURE_PATH = P2_ROOT / "fixtures" / "p2_adversarial_cases.json"
RESULTS_DIR = PILOT_ROOT / "results"
RESULT_PATH = RESULTS_DIR / "p2_adversarial_result.json"


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
        raise ValueError("P2 fixture must contain a JSON array")

    if not cases:
        raise ValueError("P2 fixture must contain at least one case")

    required = {
        "case_id",
        "description",
        "expected_outcome",
        "observed_outcome",
        "reported_status",
        "expected_label",
        "expected_verified",
        "expected_exact_match",
    }

    valid_labels = {
        "TRUE_SUCCESS",
        "FALSE_SUCCESS",
        "FAILURE",
        "FALSE_FAILURE",
    }

    seen_ids: set[str] = set()

    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Every P2 case must be an object")

        missing = required - set(case)

        if missing:
            raise ValueError(
                f"Case {case.get('case_id', '<unknown>')} "
                f"missing fields: {sorted(missing)}"
            )

        case_id = case["case_id"]

        if not isinstance(case_id, str) or not case_id:
            raise ValueError("case_id must be a non-empty string")

        if case_id in seen_ids:
            raise ValueError(f"Duplicate case_id: {case_id}")

        seen_ids.add(case_id)

        for field in (
            "expected_outcome",
            "observed_outcome",
            "reported_status",
            "description",
        ):
            if not isinstance(case[field], str) or not case[field]:
                raise ValueError(
                    f"Case {case_id}: {field} must be a non-empty string"
                )

        if case["expected_label"] not in valid_labels:
            raise ValueError(
                f"Case {case_id}: invalid expected_label"
            )

        if not isinstance(case["expected_verified"], bool):
            raise ValueError(
                f"Case {case_id}: expected_verified must be boolean"
            )

        if not isinstance(case["expected_exact_match"], bool):
            raise ValueError(
                f"Case {case_id}: expected_exact_match must be boolean"
            )


def run_case(verifier, case: dict) -> dict:
    result = verifier.verify(
        expected_outcome=case["expected_outcome"],
        observed_outcome=case["observed_outcome"],
        reported_status=case["reported_status"],
    )

    passed = (
        result.outcome_label == case["expected_label"]
        and result.verified == case["expected_verified"]
        and result.exact_match == case["expected_exact_match"]
        and result.independent_of_agent_report is True
    )

    record = {
        "case_id": case["case_id"],
        "description": case["description"],
        "expected_outcome": case["expected_outcome"],
        "observed_outcome": case["observed_outcome"],
        "reported_status": case["reported_status"],
        "expected_label": case["expected_label"],
        "actual_label": result.outcome_label,
        "expected_verified": case["expected_verified"],
        "actual_verified": result.verified,
        "expected_exact_match": case["expected_exact_match"],
        "actual_exact_match": result.exact_match,
        "independent_of_agent_report": (
            result.independent_of_agent_report
        ),
        "passed": passed,
    }

    if "paired_reported_status" in case:
        paired = verifier.verify(
            expected_outcome=case["expected_outcome"],
            observed_outcome=case["observed_outcome"],
            reported_status=case["paired_reported_status"],
        )

        record["paired_control"] = {
            "reported_status": case["paired_reported_status"],
            "outcome_label": paired.outcome_label,
            "verified": paired.verified,
            "exact_match": paired.exact_match,
            "expected_label": case["paired_expected_label"],
            "passed": (
                paired.outcome_label == case["paired_expected_label"]
                and paired.verified is False
                and paired.exact_match is False
                and paired.independent_of_agent_report is True
            ),
        }

        record["passed"] = (
            record["passed"]
            and record["paired_control"]["passed"]
        )

    return record


def build_summary(records: list[dict]) -> dict:
    total = len(records)
    passed = sum(1 for record in records if record["passed"])
    failed = total - passed

    return {
        "schema_version": "0.1.0",
        "condition": "P2_ADVERSARIAL_CONTROL",
        "case_count": total,
        "passed_cases": passed,
        "failed_cases": failed,
        "pass_rate": passed / total if total else 0.0,
        "all_cases_passed": failed == 0,
        "cases": records,
    }


def main() -> int:
    verifier_module = load_module(
        "jas_si_p2_oracle_verifier",
        PILOT_ROOT / "verifier" / "oracle_verifier.py",
    )

    cases = load_json(FIXTURE_PATH)
    validate_cases(cases)

    verifier = verifier_module.IndependentVerifier()

    records = [
        run_case(verifier, case)
        for case in cases
    ]

    result = build_summary(records)

    if not result["all_cases_passed"]:
        failed_cases = [
            record["case_id"]
            for record in records
            if not record["passed"]
        ]

        raise RuntimeError(
            "P2 adversarial control failed for cases: "
            + ", ".join(failed_cases)
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

    print("P2 adversarial control: PASS")
    print(f"Cases: {result['case_count']}")
    print(f"Passed: {result['passed_cases']}")
    print(f"Failed: {result['failed_cases']}")
    print(f"Pass rate: {result['pass_rate']:.6f}")
    print(f"Result: {RESULT_PATH}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
