
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

GATES_DIR = Path(__file__).resolve().parent

CRITERIA_PATH = GATES_DIR / "review_criteria.json"
PACKETS_PATH = GATES_DIR / "evidence_review_packets.json"

EXPECTED_PROTOCOL = "JAS-SI-V0.1-EVIDENCE-REVIEW-PACKETS"
EXPECTED_BENCHMARK_STATUS = "DEVELOPMENT_NOT_FROZEN"
ALLOWED_REVIEW_STATUSES = {
    "NOT_REVIEWED",
    "BLOCKED",
    "PASS",
    "FAIL",
}


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must contain a JSON object.")
    return data


def validate() -> list[str]:
    errors: list[str] = []

    for path in (CRITERIA_PATH, PACKETS_PATH):
        if not path.is_file():
            return [f"Required file not found: {path.name}"]

    try:
        criteria_data = read_json(CRITERIA_PATH)
        packets_data = read_json(PACKETS_PATH)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [f"Cannot read input JSON: {exc}"]

    criteria = criteria_data.get("gates")
    records = packets_data.get("records")

    if not isinstance(criteria, list):
        return ["review_criteria.json must contain a gates list."]

    if not isinstance(records, list):
        return ["evidence_review_packets.json must contain a records list."]

    if packets_data.get("protocol") != EXPECTED_PROTOCOL:
        errors.append("Unexpected review packet protocol.")

    if packets_data.get("status") != "REVIEW_PACKET_PREPARED":
        errors.append("Packet status must be REVIEW_PACKET_PREPARED.")

    if packets_data.get("benchmark_status") != EXPECTED_BENCHMARK_STATUS:
        errors.append("Benchmark must remain DEVELOPMENT_NOT_FROZEN.")

    if packets_data.get("automatic_approval") is not False:
        errors.append("automatic_approval must be false.")

    if packets_data.get("freeze_authorized") is not False:
        errors.append("freeze_authorized must be false.")

    if packets_data.get("gate_count") != len(records):
        errors.append("gate_count does not match the number of records.")

    if len(criteria) != 13:
        errors.append(f"Expected 13 review criteria; found {len(criteria)}.")

    expected_ids: list[str] = []
    for item in criteria:
        if not isinstance(item, dict) or not isinstance(
            item.get("gate_id"), str
        ):
            errors.append("Review criteria contains a malformed gate entry.")
            continue
        expected_ids.append(item["gate_id"])

    actual_ids: list[str] = []
    for item in records:
        if not isinstance(item, dict) or not isinstance(
            item.get("gate_id"), str
        ):
            errors.append("Review packets contain a malformed record.")
            continue
        actual_ids.append(item["gate_id"])

    if len(expected_ids) != len(set(expected_ids)):
        errors.append("Duplicate gate IDs found in review criteria.")

    if len(actual_ids) != len(set(actual_ids)):
        errors.append("Duplicate gate IDs found in review packets.")

    if set(actual_ids) != set(expected_ids):
        errors.append("Gate IDs do not match the review criteria.")

    for packet in records:
        if not isinstance(packet, dict):
            continue

        gate_id = packet.get("gate_id", "<unknown>")

        if packet.get("gate_approval") != "NOT_GRANTED":
            errors.append(f"{gate_id}: gate approval must remain NOT_GRANTED.")

        if packet.get("human_review_required") is not True:
            errors.append(f"{gate_id}: human review must be required.")

        if packet.get("review_status") not in ALLOWED_REVIEW_STATUSES:
            errors.append(f"{gate_id}: invalid review_status.")

        candidate_files = packet.get("candidate_files")
        if not isinstance(candidate_files, list):
            errors.append(f"{gate_id}: candidate_files must be a list.")

        required_evidence = packet.get("required_evidence")
        if not isinstance(required_evidence, list):
            errors.append(f"{gate_id}: required_evidence must be a list.")
        else:
            for item in required_evidence:
                if not isinstance(item, dict):
                    errors.append(
                        f"{gate_id}: malformed required evidence item."
                    )
                    continue

                if item.get("review_result") not in {
                    "NOT_REVIEWED",
                    "PASS",
                    "FAIL",
                    "BLOCKED",
                }:
                    errors.append(
                        f"{gate_id}: invalid evidence review_result."
                    )

        review_checks = packet.get("review_checks")
        if not isinstance(review_checks, list):
            errors.append(f"{gate_id}: review_checks must be a list.")
        else:
            for item in review_checks:
                if not isinstance(item, dict):
                    errors.append(f"{gate_id}: malformed review check.")
                    continue

                if item.get("result") not in {
                    "NOT_REVIEWED",
                    "PASS",
                    "FAIL",
                    "BLOCKED",
                }:
                    errors.append(f"{gate_id}: invalid review check result.")

        decision = packet.get("review_decision")
        if not isinstance(decision, dict):
            errors.append(f"{gate_id}: review_decision must be an object.")
        else:
            if decision.get("reviewer") is not None:
                errors.append(
                    f"{gate_id}: generated packet must not invent a reviewer."
                )

            if decision.get("reviewed_at") is not None:
                errors.append(
                    f"{gate_id}: generated packet must not invent a review time."
                )

    return errors


def main() -> int:
    errors = validate()

    if errors:
        print("EVIDENCE REVIEW PACKET VALIDATION: FAILED")
        for error in errors:
            print(f"- {error}")
        return 1

    print("EVIDENCE REVIEW PACKET VALIDATION: PASSED")
    print("Gate packets validated: 13")
    print("Automatic approvals: none")
    print("Benchmark freeze: not authorized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
