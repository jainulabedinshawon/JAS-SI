
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CRITERIA_FILE = ROOT / "review_criteria.json"

REQUIRED_GATES = {
    "P0", "P1", "P2", "P3", "P4", "P5",
    "P6", "P7", "P8", "P9", "P10",
    "CONTENT_FREEZE", "CONFIG_FREEZE",
}


def main() -> int:
    data = json.loads(CRITERIA_FILE.read_text(encoding="utf-8"))
    errors: list[str] = []

    if data.get("status") != "REVIEW_PLAN_ONLY":
        errors.append("status must remain REVIEW_PLAN_ONLY")

    gates = data.get("gates")
    if not isinstance(gates, list):
        print("FAIL: gates must be a list")
        return 1

    ids = [
        gate.get("gate_id")
        for gate in gates
        if isinstance(gate, dict)
    ]

    if len(ids) != len(set(ids)):
        errors.append("duplicate gate IDs detected")

    if set(ids) != REQUIRED_GATES:
        errors.append(
            f"gate IDs mismatch; missing={sorted(REQUIRED_GATES - set(ids))}, "
            f"extra={sorted(set(ids) - REQUIRED_GATES)}"
        )

    for gate in gates:
        if not isinstance(gate, dict):
            errors.append("each gate must be an object")
            continue

        gate_id = gate.get("gate_id", "UNKNOWN")

        for field in ("required_evidence", "review_checks"):
            values = gate.get(field)

            if not isinstance(values, list) or not values:
                errors.append(f"{gate_id}: {field} must be a non-empty list")
            elif any(
                not isinstance(value, str) or not value.strip()
                for value in values
            ):
                errors.append(f"{gate_id}: {field} contains an empty item")

    if errors:
        print("REVIEW CRITERIA VALIDATION: FAIL")
        for error in errors:
            print(f"- {error}")
        return 1

    print("REVIEW CRITERIA VALIDATION: PASS")
    print(f"Gate criteria checked: {len(gates)}")
    print("This validates checklist structure only.")
    print("It does not approve evidence or freeze the benchmark.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
