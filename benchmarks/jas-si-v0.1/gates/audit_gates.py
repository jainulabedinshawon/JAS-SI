
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REGISTRY = ROOT / "evidence_registry.json"
RESULTS = ROOT / "audit_result.json"

ALLOWED_STATUSES = {
    "NOT_REVIEWED",
    "BLOCKED",
    "PASS",
    "FAIL",
}

REQUIRED_GATES = [
    "P0", "P1", "P2", "P3", "P4", "P5", "P6",
    "P7", "P8", "P9", "P10", "CONTENT_FREEZE", "CONFIG_FREEZE",
]


def validate_registry(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    gates = data.get("gates")

    if not isinstance(gates, list):
        return ["gates must be a list"]

    ids = [gate.get("gate_id") for gate in gates if isinstance(gate, dict)]

    if len(ids) != len(set(ids)):
        errors.append("duplicate gate_id detected")

    missing = set(REQUIRED_GATES) - set(ids)
    extra = set(ids) - set(REQUIRED_GATES)

    if missing:
        errors.append(f"missing required gates: {sorted(missing)}")
    if extra:
        errors.append(f"unexpected gates: {sorted(extra)}")

    for gate in gates:
        if not isinstance(gate, dict):
            errors.append("each gate must be an object")
            continue

        gate_id = gate.get("gate_id", "UNKNOWN")
        status = gate.get("status")
        refs = gate.get("evidence_refs")

        if status not in ALLOWED_STATUSES:
            errors.append(f"{gate_id}: invalid status {status!r}")

        if not isinstance(refs, list):
            errors.append(f"{gate_id}: evidence_refs must be a list")
            continue

        if status == "PASS" and not refs:
            errors.append(f"{gate_id}: PASS requires evidence_refs")

        if any(
            not isinstance(ref, str) or not ref.strip()
            for ref in refs
        ):
            errors.append(f"{gate_id}: evidence refs must be non-empty strings")

    return errors


def main() -> int:
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    errors = validate_registry(data)

    if errors:
        report = {
            "audit": "JAS-SI_V0.1_EVIDENCE_GATE_AUDIT",
            "registry_valid": False,
            "freeze_ready": False,
            "errors": errors,
        }
        exit_code = 1
    else:
        gates = data["gates"]
        unpassed = [
            gate["gate_id"]
            for gate in gates
            if gate["status"] != "PASS"
        ]

        report = {
            "audit": "JAS-SI_V0.1_EVIDENCE_GATE_AUDIT",
            "registry_valid": True,
            "benchmark_status": data.get(
                "benchmark_status", "UNKNOWN"
            ),
            "total_gates": len(gates),
            "passed_gates": sum(
                gate["status"] == "PASS" for gate in gates
            ),
            "unpassed_gate_ids": unpassed,
            "freeze_ready": len(unpassed) == 0,
            "decision": (
                "READY_FOR_INDEPENDENT_FREEZE_REVIEW"
                if not unpassed
                else "NOT_READY_FOR_FREEZE"
            ),
            "limitations": [
                "This script checks registry structure, not evidence truth.",
                "Evidence references require human review.",
                "PASS statuses must only be assigned after review.",
                "Synthetic development results do not establish benchmark validity."
            ],
        }
        exit_code = 0

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
