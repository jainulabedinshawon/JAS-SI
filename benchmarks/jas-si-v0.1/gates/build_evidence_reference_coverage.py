
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent

REGISTRY_PATH = ROOT / "evidence_registry.json"
CRITERIA_PATH = ROOT / "review_criteria.json"
LEDGER_PATH = ROOT / "review_ledger.json"

JSON_OUTPUT = ROOT / "evidence_reference_coverage.json"
MD_OUTPUT = ROOT / "evidence_reference_coverage.md"

EXPECTED_PROTOCOL = "JAS-SI-V0.1-EVIDENCE-REFERENCE-COVERAGE"
EXPECTED_STATUS = "DEVELOPMENT_NOT_FROZEN"

EXPECTED_GATES = {
    "P0", "P1", "P2", "P3", "P4", "P5",
    "P6", "P7", "P8", "P9", "P10",
    "CONTENT_FREEZE", "CONFIG_FREEZE",
}


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must contain a JSON object.")

    return data


def index_records(
    records: Any,
    source_name: str,
    expected_key: str,
) -> dict[str, dict[str, Any]]:
    if not isinstance(records, list):
        raise ValueError(f"{source_name} records must be a list.")

    indexed: dict[str, dict[str, Any]] = {}

    for record in records:
        if not isinstance(record, dict):
            raise ValueError(
                f"{source_name} contains a non-object record."
            )

        gate_id = record.get(expected_key)

        if not isinstance(gate_id, str) or not gate_id:
            raise ValueError(
                f"{source_name} contains an invalid gate ID."
            )

        if gate_id in indexed:
            raise ValueError(
                f"{source_name} contains duplicate gate ID: {gate_id}"
            )

        indexed[gate_id] = record

    if set(indexed) != EXPECTED_GATES:
        raise ValueError(
            f"{source_name} gate IDs do not match the 13 expected gates."
        )

    return indexed


def build_report() -> dict[str, Any]:
    registry = read_json(REGISTRY_PATH)
    criteria_data = read_json(CRITERIA_PATH)
    ledger = read_json(LEDGER_PATH)

    for name, data in (
        ("registry", registry),
        ("review criteria", criteria_data),
        ("review ledger", ledger),
    ):
        if data.get("benchmark_status") != EXPECTED_STATUS:
            raise ValueError(
                f"{name} must remain {EXPECTED_STATUS}."
            )

    if registry.get("protocol") != "JAS-SI-V0.1-EVIDENCE-GATE-AUDIT":
        raise ValueError("Unexpected evidence registry protocol.")

    if criteria_data.get("status") != "REVIEW_PLAN_ONLY":
        raise ValueError("Review criteria must remain a review plan.")

    if ledger.get("protocol") != "JAS-SI-V0.1-REVIEW-LEDGER":
        raise ValueError("Unexpected review ledger protocol.")

    registry_by_id = index_records(
        registry.get("gates"),
        "evidence registry",
        "gate_id",
    )
    criteria_by_id = index_records(
        criteria_data.get("gates"),
        "review criteria",
        "gate_id",
    )
    ledger_by_id = index_records(
        ledger.get("records"),
        "review ledger",
        "gate_id",
    )

    records = []

    for gate_id in sorted(
        EXPECTED_GATES,
        key=lambda item: (
            int(item[1:]) if item.startswith("P")
            and item[1:].isdigit() else 100
        ),
    ):
        gate = registry_by_id[gate_id]
        criterion = criteria_by_id[gate_id]
        review = ledger_by_id[gate_id]

        refs = gate.get("evidence_refs")
        required_evidence = criterion.get("required_evidence")
        checks = criterion.get("review_checks")

        if not isinstance(refs, list):
            raise ValueError(
                f"{gate_id}: evidence_refs must be a list."
            )

        if not isinstance(required_evidence, list):
            raise ValueError(
                f"{gate_id}: required_evidence must be a list."
            )

        if not isinstance(checks, list):
            raise ValueError(
                f"{gate_id}: review_checks must be a list."
            )

        ledger_refs = review.get("evidence_refs")

        if not isinstance(ledger_refs, list):
            raise ValueError(
                f"{gate_id}: ledger evidence_refs must be a list."
            )

        valid_registry_refs = [
            ref for ref in refs
            if isinstance(ref, str) and ref.startswith("https://github.com/")
        ]

        valid_ledger_refs = [
            ref for ref in ledger_refs
            if isinstance(ref, str)
            and ref.startswith("https://github.com/")
        ]

        records.append({
            "gate_id": gate_id,
            "gate_name": gate.get("name", gate_id),
            "registry_status": gate.get("status", "UNKNOWN"),
            "review_status": review.get("status", "UNKNOWN"),
            "required_evidence_count": len(required_evidence),
            "review_check_count": len(checks),
            "registry_reference_count": len(refs),
            "registry_valid_github_url_count": len(valid_registry_refs),
            "ledger_reference_count": len(ledger_refs),
            "ledger_valid_github_url_count": len(valid_ledger_refs),
            "registry_references_missing": len(refs) == 0,
            "human_review_required": True,
            "gate_approval": "NOT_GRANTED",
            "gate_passed": False,
        })

    missing_registry = sum(
        item["registry_references_missing"] for item in records
    )

    missing_ledger = sum(
        item["ledger_reference_count"] == 0 for item in records
    )

    return {
        "protocol": EXPECTED_PROTOCOL,
        "report_status": "COVERAGE_AUDIT_ONLY",
        "benchmark_status": EXPECTED_STATUS,
        "gate_count": len(records),
        "gates_without_registry_references": missing_registry,
        "gates_without_ledger_references": missing_ledger,
        "automatic_approval": False,
        "freeze_authorized": False,
        "limitations": [
            "A reference URL does not prove evidence authenticity.",
            "A successful workflow does not automatically pass a gate.",
            "Reference counts do not prove that every evidence requirement is met.",
            "Review decisions require independent human assessment.",
            "This report does not modify the registry or review ledger.",
        ],
        "records": records,
    }


def build_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# JAS-SI v0.1 — Evidence Reference Coverage",
        "",
        "**Report status:** `COVERAGE_AUDIT_ONLY`",
        "",
        "**Benchmark status:** `DEVELOPMENT_NOT_FROZEN`",
        "",
        f"- Gates indexed: {report['gate_count']}",
        (
            "- Gates without registry references: "
            f"{report['gates_without_registry_references']}"
        ),
        (
            "- Gates without ledger references: "
            f"{report['gates_without_ledger_references']}"
        ),
        "- Automatic approval: DISABLED",
        "- Benchmark freeze: NOT AUTHORIZED",
        "",
        "| Gate | Registry status | Review status | Required evidence | Checks | Registry refs | Ledger refs |",
        "|---|---|---|---:|---:|---:|---:|",
    ]

    for item in report["records"]:
        lines.append(
            f"| {item['gate_id']} "
            f"| {item['registry_status']} "
            f"| {item['review_status']} "
            f"| {item['required_evidence_count']} "
            f"| {item['review_check_count']} "
            f"| {item['registry_reference_count']} "
            f"| {item['ledger_reference_count']} |"
        )

    lines.extend([
        "",
        "## Interpretation",
        "",
        "This report measures reference coverage only. It does not establish",
        "that referenced artifacts exist, are authentic, or satisfy a gate.",
        "",
        "## Limitations",
        "",
    ])

    for limitation in report["limitations"]:
        lines.append(f"- {limitation}")

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    try:
        report = build_report()

        JSON_OUTPUT.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        MD_OUTPUT.write_text(
            build_markdown(report),
            encoding="utf-8",
        )

    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"EVIDENCE COVERAGE AUDIT: FAILED — {exc}")
        return 1

    print("EVIDENCE COVERAGE AUDIT: GENERATED")
    print(f"Gate records: {report['gate_count']}")
    print(
        "Without registry references:",
        report["gates_without_registry_references"],
    )
    print(
        "Without ledger references:",
        report["gates_without_ledger_references"],
    )
    print("Automatic gate approvals: none")
    print("Benchmark freeze: not authorized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
