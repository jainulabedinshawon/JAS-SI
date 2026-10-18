
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
INVENTORY_PATH = (
    REPO_ROOT
    / "benchmarks"
    / "jas-si-v0.1"
    / "gates"
    / "evidence_inventory.json"
)

EXPECTED_PROTOCOL = "JAS-SI-V0.1-EVIDENCE-INVENTORY"

EXPECTED_GATES = {
    "P0",
    "P1",
    "P2",
    "P3",
    "P4",
    "P5",
    "P6",
    "P7",
    "P8",
    "P9",
    "P10",
    "CONTENT_FREEZE",
    "CONFIG_FREEZE",
}


def validate_inventory(
    report: dict[str, Any],
    repo_root: Path,
) -> list[str]:
    errors: list[str] = []

    if report.get("protocol") != EXPECTED_PROTOCOL:
        errors.append("Unexpected inventory protocol.")

    if report.get("inventory_status") != "DISCOVERY_ONLY":
        errors.append("Inventory must remain DISCOVERY_ONLY.")

    if report.get("benchmark_status") != "DEVELOPMENT_NOT_FROZEN":
        errors.append("Benchmark must remain DEVELOPMENT_NOT_FROZEN.")

    records = report.get("records")
    if not isinstance(records, list):
        return errors + ["'records' must be a list."]

    actual_ids = [
        record.get("gate_id")
        for record in records
        if isinstance(record, dict)
    ]

    if len(records) != 13:
        errors.append("Expected exactly 13 gate records.")

    if len(actual_ids) != len(records):
        errors.append("Every record must be a JSON object.")

    if len(set(actual_ids)) != len(actual_ids):
        errors.append("Duplicate gate IDs found.")

    if set(actual_ids) != EXPECTED_GATES:
        errors.append("Gate IDs do not match the expected set.")

    if report.get("gate_count") != 13:
        errors.append("'gate_count' must equal 13.")

    if not isinstance(report.get("repository_file_count"), int):
        errors.append("'repository_file_count' must be an integer.")
    elif report["repository_file_count"] < 0:
        errors.append("'repository_file_count' cannot be negative.")

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue

        prefix = f"Record {index}"

        candidates = record.get("candidate_files")
        if not isinstance(candidates, list):
            errors.append(f"{prefix}: candidate_files must be a list.")
            continue

        expected_status = (
            "CANDIDATES_FOUND"
            if candidates
            else "NO_CANDIDATES_FOUND"
        )

        if record.get("status") != expected_status:
            errors.append(
                f"{prefix}: status does not match candidate list."
            )

        if record.get("human_review_required") is not True:
            errors.append(
                f"{prefix}: human review must remain required."
            )

        if record.get("gate_passed") is not False:
            errors.append(
                f"{prefix}: inventory must never approve a gate."
            )

        for candidate in candidates:
            if not isinstance(candidate, str) or not candidate:
                errors.append(
                    f"{prefix}: invalid candidate path."
                )
                continue

            candidate_path = Path(candidate)

            if candidate_path.is_absolute() or ".." in candidate_path.parts:
                errors.append(
                    f"{prefix}: unsafe candidate path: {candidate}"
                )
                continue

            resolved = (repo_root / candidate_path).resolve()

            try:
                resolved.relative_to(repo_root.resolve())
            except ValueError:
                errors.append(
                    f"{prefix}: path escapes repository: {candidate}"
                )
                continue

            if not resolved.is_file():
                errors.append(
                    f"{prefix}: candidate file does not exist: {candidate}"
                )

    return errors


def main() -> int:
    if not INVENTORY_PATH.is_file():
        print(
            f"ERROR: Inventory file not found: {INVENTORY_PATH}",
            file=sys.stderr,
        )
        return 1

    try:
        report = json.loads(
            INVENTORY_PATH.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: Cannot read inventory JSON: {exc}", file=sys.stderr)
        return 1

    if not isinstance(report, dict):
        print("ERROR: Inventory root must be a JSON object.", file=sys.stderr)
        return 1

    errors = validate_inventory(report, REPO_ROOT)

    if errors:
        print("EVIDENCE INVENTORY VALIDATION: FAILED")
        for error in errors:
            print(f"- {error}")
        return 1

    print("EVIDENCE INVENTORY VALIDATION: PASSED")
    print(f"Gate records: {len(report['records'])}")
    print("Candidate file references: valid")
    print("Automatic gate approvals: none")
    print("Benchmark freeze: not authorized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
