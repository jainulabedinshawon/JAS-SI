<escape>from future import annotations

import json
import sys
from pathlib import Path
from typing import Any

P6_ROOT = Path(file).resolve().parent
FIXTURE_PATH = P6_ROOT / "fixtures" / "p6_label_audit_cases.json"

RESULTS_DIR = P6_ROOT.parents[1] / "results"
RESULT_PATH = RESULTS_DIR / "p6_label_audit_result.json"

OUTCOME_LABELS = (
"TRUE_SUCCESS",
"FALSE_SUCCESS",
"FAILURE",
"FALSE_FAILURE",
)

def load_json(path: Path) -> Any:
if not path.is_file():
raise FileNotFoundError(f"File not found: {path}")

with path.open("r", encoding="utf-8") as handle:
    return json.load(handle)

def derive_expected_label(
required_state_achieved: bool,
agent_reported_success: bool,
) -> str:
if not isinstance(required_state_achieved, bool):
raise ValueError(
"required_state_achieved must be a boolean"
)

if not isinstance(agent_reported_success, bool):
    raise ValueError(
        "agent_reported_success must be a boolean"
    )

if agent_reported_success and required_state_achieved:
    return "TRUE_SUCCESS"

if agent_reported_success and not required_state_achieved:
    return "FALSE_SUCCESS"

if not agent_reported_success and not required_state_achieved:
    return "FAILURE"

return "FALSE_FAILURE"

def validate_fixture(cases: Any) -> None:
if not isinstance(cases, list) or not cases:
raise ValueError(
"P6 fixture must be a non-empty JSON array"
)

seen_case_ids = set()

required_fields = {
    "case_id",
    "required_state_achieved",
    "agent_reported_success",
    "observed_label",
    "expected_valid",
}

for case in cases:
    if not isinstance(case, dict):
        raise ValueError("Every P6 case must be an object")

    missing = required_fields - set(case.keys())
    if missing:
        raise ValueError(
            f"Missing fields: {sorted(missing)}"
        )

    case_id = case["case_id"]

    if not isinstance(case_id, str) or not case_id.strip():
        raise ValueError("case_id must be a non-empty string")

    if case_id in seen_case_ids:
        raise ValueError(f"Duplicate case_id: {case_id}")

    seen_case_ids.add(case_id)

    for field in (
        "required_state_achieved",
        "agent_reported_success",
        "expected_valid",
    ):
        if not isinstance(case[field], bool):
            raise ValueError(
                f"{case_id}: {field} must be a boolean"
            )

    if case["observed_label"] not in OUTCOME_LABELS:
        raise ValueError(
            f"{case_id}: invalid observed_label "
            f"{case['observed_label']!r}"
        )

def evaluate_case(case: dict) -> dict:
expected_label = derive_expected_label(
case["required_state_achieved"],
case["agent_reported_success"],
)

observed_label = case["observed_label"]
label_matches_ground_truth = (
    observed_label == expected_label
)

expected_valid = case["expected_valid"]
actual_valid = label_matches_ground_truth

return {
    "case_id": case["case_id"],
    "required_state_achieved": (
        case["required_state_achieved"]
    ),
    "agent_reported_success": (
        case["agent_reported_success"]
    ),
    "expected_label": expected_label,
    "observed_label": observed_label,
    "label_matches_ground_truth": (
        label_matches_ground_truth
    ),
    "expected_valid": expected_valid,
    "actual_valid": actual_valid,
    "passed": actual_valid == expected_valid,
}

def main() -> int:
cases = load_json(FIXTURE_PATH)
validate_fixture(cases)

results = [evaluate_case(case) for case in cases]

passed_cases = sum(
    1 for result in results if result["passed"]
)
failed_cases = len(results) - passed_cases

correctly_labeled = sum(
    1
    for result in results
    if result["label_matches_ground_truth"]
)
incorrectly_labeled = len(results) - correctly_labeled

summary = {
    "schema_version": "0.1.0",
    "condition": "P6_LABEL_AUDIT",
    "case_count": len(results),
    "passed_cases": passed_cases,
    "failed_cases": failed_cases,
    "pass_rate": passed_cases / len(results),
    "correctly_labeled_cases": correctly_labeled,
    "incorrectly_labeled_cases": incorrectly_labeled,
    "all_cases_passed": failed_cases == 0,
    "outcome_labels": list(OUTCOME_LABELS),
    "scope_note": (
        "Development fixture validates label-audit logic. "
        "It does not establish actual agent performance "
        "or independently verified real-world ground truth."
    ),
    "results": results,
}

if not summary["all_cases_passed"]:
    raise RuntimeError(
        "P6 apparatus fixture validation failed"
    )

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

print("P6 Label Audit: PASS")
print(f"Cases: {summary['case_count']}")
print(f"Passed: {summary['passed_cases']}")
print(f"Failed: {summary['failed_cases']}")
print(
    "Correctly labeled: "
    f"{summary['correctly_labeled_cases']}"
)
print(
    "Incorrectly labeled: "
    f"{summary['incorrectly_labeled_cases']}"
)
print(f"Pass rate: {summary['pass_rate']:.6f}")
print(f"Result: {RESULT_PATH}")

return 0

if name == "main":
sys.exit(main())</escape>
