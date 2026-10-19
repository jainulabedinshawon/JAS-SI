
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

GATES_DIR = Path(__file__).resolve().parent
BENCHMARK_ROOT = GATES_DIR.parent

CRITERIA_PATH = GATES_DIR / "review_criteria.json"
LEDGER_PATH = GATES_DIR / "review_ledger.json"
INVENTORY_PATH = GATES_DIR / "evidence_inventory.json"
OUTPUT_PATH = GATES_DIR / "evidence_review_packets.json"

EXPECTED_PROTOCOL = "JAS-SI-V0.1-EVIDENCE-REVIEW-PACKETS"
EXPECTED_BENCHMARK_STATUS = "DEVELOPMENT_NOT_FROZEN"


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object: {path.name}")
    return data


def main() -> int:
    for path in (CRITERIA_PATH, LEDGER_PATH, INVENTORY_PATH):
        if not path.is_file():
            print(f"ERROR: Required input not found: {path.name}")
            return 1

    try:
        criteria_data = read_json(CRITERIA_PATH)
        ledger_data = read_json(LEDGER_PATH)
        inventory_data = read_json(INVENTORY_PATH)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: Cannot read input data: {exc}")
        return 1

    criteria = criteria_data.get("gates")
    ledger_records = ledger_data.get("records")
    inventory_records = inventory_data.get("records")

    if not isinstance(criteria, list):
        print("ERROR: review_criteria.json must contain a gates list.")
        return 1

    if not isinstance(ledger_records, list):
        print("ERROR: review_ledger.json must contain a records list.")
        return 1

    if not isinstance(inventory_records, list):
        print("ERROR: evidence_inventory.json must contain a records list.")
        return 1

    ledger_by_id = {
        record.get("gate_id"): record
        for record in ledger_records
        if isinstance(record, dict)
    }
    inventory_by_id = {
        record.get("gate_id"): record
        for record in inventory_records
        if isinstance(record, dict)
    }

    criteria_ids = {
        record.get("gate_id")
        for record in criteria
        if isinstance(record, dict)
    }

    if len(criteria_ids) != len(criteria):
        print("ERROR: Duplicate or malformed gate IDs in review criteria.")
        return 1

    if criteria_ids != set(ledger_by_id) or criteria_ids != set(inventory_by_id):
        print("ERROR: Gate IDs differ across criteria, ledger, and inventory.")
        return 1

    packets = []

    for criterion in criteria:
        if not isinstance(criterion, dict):
            print("ERROR: Every criterion must be an object.")
            return 1

        gate_id = criterion.get("gate_id")
        ledger_record = ledger_by_id[gate_id]
        inventory_record = inventory_by_id[gate_id]

        required_evidence = criterion.get("required_evidence", [])
        review_checks = criterion.get("review_checks", [])

        if not isinstance(required_evidence, list):
            print(f"ERROR: {gate_id}: required_evidence must be a list.")
            return 1

        if not isinstance(review_checks, list):
            print(f"ERROR: {gate_id}: review_checks must be a list.")
            return 1

        packets.append({
            "gate_id": gate_id,
            "review_status": ledger_record.get("status", "NOT_REVIEWED"),
            "gate_approval": "NOT_GRANTED",
            "human_review_required": True,
            "candidate_files": inventory_record.get("candidate_files", []),
            "required_evidence": [
                {
                    "requirement": item,
                    "evidence_url": None,
                    "workflow_run_id": None,
                    "commit_sha": None,
                    "artifact_name": None,
                    "review_result": "NOT_REVIEWED",
                    "reviewer_notes": "",
                }
                for item in required_evidence
            ],
            "review_checks": [
                {
                    "check": item,
                    "result": "NOT_REVIEWED",
                    "notes": "",
                }
                for item in review_checks
            ],
            "review_decision": {
                "reviewer": None,
                "reviewed_at": None,
                "decision_notes": "",
            },
            "limitations": [
                "Candidate filenames are discovery hints, not proof.",
                "Evidence URLs and run IDs must be verified by a human.",
                "Successful workflow status alone does not establish gate validity.",
                "Synthetic fixture results must not be presented as real-agent performance.",
            ],
        })

    report = {
        "protocol": EXPECTED_PROTOCOL,
        "status": "REVIEW_PACKET_PREPARED",
        "benchmark_status": EXPECTED_BENCHMARK_STATUS,
        "automatic_approval": False,
        "freeze_authorized": False,
        "gate_count": len(packets),
        "source_files": {
            "criteria": CRITERIA_PATH.relative_to(BENCHMARK_ROOT.parent).as_posix(),
            "ledger": LEDGER_PATH.relative_to(BENCHMARK_ROOT.parent).as_posix(),
            "inventory": INVENTORY_PATH.relative_to(BENCHMARK_ROOT.parent).as_posix(),
        },
        "records": packets,
    }

    OUTPUT_PATH.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("EVIDENCE REVIEW PACKETS: GENERATED")
    print(f"Gate packets: {len(packets)}")
    print(f"Output: {OUTPUT_PATH.relative_to(BENCHMARK_ROOT.parent)}")
    print("Automatic approvals: none")
    print("Benchmark freeze: not authorized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
