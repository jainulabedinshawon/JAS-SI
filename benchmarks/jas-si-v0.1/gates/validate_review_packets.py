
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

GATES_DIR = Path(__file__).resolve().parent
CRITERIA_PATH = GATES_DIR / "review_criteria.json"
PACKETS_PATH = GATES_DIR / "evidence_review_packets.json"

EXPECTED_PROTOCOL = "JAS-SI-V0.1-EVIDENCE-REVIEW-PACKETS"
EXPECTED_BENCHMARK_STATUS = "DEVELOPMENT_NOT_FROZEN"

ALLOWED_STATUSES = {"NOT_REVIEWED", "BLOCKED", "PASS", "FAIL"}
REQUIRED_EVIDENCE_FIELDS = {
    "requirement",
    "evidence_url",
    "workflow_run_id",
    "commit_sha",
    "artifact_name",
    "review_result",
    "reviewer_notes",
}
REQUIRED_CHECK_FIELDS = {"check", "result", "notes"}
SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


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
        packet_data = read_json(PACKETS_PATH)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [f"Cannot read JSON input: {exc}"]

    criteria = criteria_data.get("gates")
    packets = packet_data.get("records")

    if not isinstance(criteria, list):
        return ["review_criteria.json must contain a gates list."]
    if not isinstance(packets, list):
        return ["evidence_review_packets.json must contain a records list."]

    if packet_data.get("protocol") != EXPECTED_PROTOCOL:
        errors.append("Unexpected packet protocol.")
    if packet_data.get("status") != "REVIEW_PACKET_PREPARED":
        errors.append("Invalid packet status.")
    if packet_data.get("benchmark_status") != EXPECTED_BENCHMARK_STATUS:
        errors.append("Benchmark must remain DEVELOPMENT_NOT_FROZEN.")
    if packet_data.get("automatic_approval") is not False:
        errors.append("Automatic approval must remain disabled.")
    if packet_data.get("freeze_authorized") is not False:
        errors.append("Freeze authorization must remain disabled.")
    if packet_data.get("gate_count") != len(packets):
        errors.append("gate_count does not match packet record count.")
    if len(criteria) != 13:
        errors.append(f"Expected 13 criteria; found {len(criteria)}.")

    criteria_by_id: dict[str, dict[str, Any]] = {}
    for item in criteria:
        if not isinstance(item, dict):
            errors.append("Malformed criterion record.")
            continue

        gate_id = item.get("gate_id")
        if not isinstance(gate_id, str) or not gate_id:
            errors.append("Criterion has a missing or invalid gate_id.")
            continue
        if gate_id in criteria_by_id:
            errors.append(f"Duplicate criterion gate ID: {gate_id}")
        criteria_by_id[gate_id] = item

    packets_by_id: dict[str, dict[str, Any]] = {}
    for item in packets:
        if not isinstance(item, dict):
            errors.append("Malformed packet record.")
            continue

        gate_id = item.get("gate_id")
        if not isinstance(gate_id, str) or not gate_id:
            errors.append("Packet has a missing or invalid gate_id.")
            continue
        if gate_id in packets_by_id:
            errors.append(f"Duplicate packet gate ID: {gate_id}")
        packets_by_id[gate_id] = item

    if set(criteria_by_id) != set(packets_by_id):
        errors.append("Packet gate IDs do not match criteria gate IDs.")

    for gate_id, criterion in criteria_by_id.items():
        packet = packets_by_id.get(gate_id)
        if packet is None:
            continue

        if packet.get("gate_approval") != "NOT_GRANTED":
            errors.append(f"{gate_id}: gate approval must remain NOT_GRANTED.")
        if packet.get("human_review_required") is not True:
            errors.append(f"{gate_id}: human review must be required.")
        if packet.get("review_status") not in ALLOWED_STATUSES:
            errors.append(f"{gate_id}: invalid review_status.")

        expected_evidence = criterion.get("required_evidence")
        actual_evidence = packet.get("required_evidence")

        if not isinstance(expected_evidence, list):
            errors.append(f"{gate_id}: criteria required_evidence is not a list.")
            expected_evidence = []

        if not isinstance(actual_evidence, list):
            errors.append(f"{gate_id}: packet required_evidence is not a list.")
            actual_evidence = []

        actual_requirements: list[str] = []
        for entry in actual_evidence:
            if not isinstance(entry, dict):
                errors.append(f"{gate_id}: malformed evidence entry.")
                continue

            missing = REQUIRED_EVIDENCE_FIELDS - set(entry)
            if missing:
                errors.append(
                    f"{gate_id}: evidence entry missing fields {sorted(missing)}."
                )

            requirement = entry.get("requirement")
            if isinstance(requirement, str):
                actual_requirements.append(requirement)
            else:
                errors.append(f"{gate_id}: invalid evidence requirement.")

            if entry.get("review_result") not in ALLOWED_STATUSES:
                errors.append(f"{gate_id}: invalid evidence review_result.")

            url = entry.get("evidence_url")
            if url is not None and (
                not isinstance(url, str)
                or not url.startswith("https://github.com/")
            ):
                errors.append(f"{gate_id}: evidence_url must be a GitHub HTTPS URL.")

            run_id = entry.get("workflow_run_id")
            if run_id is not None and (
                not str(run_id).isdigit()
            ):
                errors.append(f"{gate_id}: workflow_run_id must be numeric.")

            sha = entry.get("commit_sha")
            if sha is not None and (
                not isinstance(sha, str) or not SHA_PATTERN.fullmatch(sha)
            ):
                errors.append(f"{gate_id}: commit_sha must be a full 40-character SHA.")

            artifact = entry.get("artifact_name")
            if artifact is not None and (
                not isinstance(artifact, str) or not artifact.strip()
            ):
                errors.append(f"{gate_id}: artifact_name cannot be blank when supplied.")

        if actual_requirements != expected_evidence:
            errors.append(
                f"{gate_id}: packet evidence requirements differ from criteria."
            )

        expected_checks = criterion.get("review_checks")
        actual_checks = packet.get("review_checks")

        if not isinstance(expected_checks, list):
            errors.append(f"{gate_id}: criteria review_checks is not a list.")
            expected_checks = []

        if not isinstance(actual_checks, list):
            errors.append(f"{gate_id}: packet review_checks is not a list.")
            actual_checks = []

        actual_check_names: list[str] = []
        for check in actual_checks:
            if not isinstance(check, dict):
                errors.append(f"{gate_id}: malformed review check.")
                continue

            missing = REQUIRED_CHECK_FIELDS - set(check)
            if missing:
                errors.append(
                    f"{gate_id}: review check missing fields {sorted(missing)}."
                )

            name = check.get("check")
            if isinstance(name, str):
                actual_check_names.append(name)
            else:
                errors.append(f"{gate_id}: invalid review check name.")

            if check.get("result") not in ALLOWED_STATUSES:
                errors.append(f"{gate_id}: invalid review check result.")

        if actual_check_names != expected_checks:
            errors.append(
                f"{gate_id}: packet review checks differ from criteria."
            )

        decision = packet.get("review_decision")
        if not isinstance(decision, dict):
            errors.append(f"{gate_id}: review_decision must be an object.")
        else:
            if decision.get("reviewer") is not None:
                errors.append(f"{gate_id}: reviewer must not be invented.")
            if decision.get("reviewed_at") is not None:
                errors.append(f"{gate_id}: review timestamp must not be invented.")

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
    print("Criteria-to-packet consistency: verified")
    print("Automatic approvals: none")
    print("Benchmark freeze: not authorized")
    print("Note: reference syntax checks do not prove evidence authenticity.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
