
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / "review_ledger.json"

REQUIRED_GATES = {
    "P0", "P1", "P2", "P3", "P4", "P5",
    "P6", "P7", "P8", "P9", "P10",
    "CONTENT_FREEZE", "CONFIG_FREEZE",
}

ALLOWED_STATUSES = {
    "NOT_REVIEWED", "BLOCKED", "PASS", "FAIL"
}

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def valid_github_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return (
        parsed.scheme == "https"
        and parsed.hostname in {"github.com", "api.github.com"}
        and bool(parsed.path.strip("/"))
    )


def valid_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.tzinfo is not None
    except ValueError:
        return False


def validate(data: dict) -> list[str]:
    errors: list[str] = []

    if data.get("protocol") != "JAS-SI-V0.1-REVIEW-LEDGER":
        errors.append("Incorrect protocol identifier")

    if data.get("benchmark_status") != "DEVELOPMENT_NOT_FROZEN":
        errors.append("Benchmark must remain marked as not frozen")

    records = data.get("records")
    if not isinstance(records, list):
        return errors + ["records must be a list"]

    ids = [
        record.get("gate_id")
        for record in records
        if isinstance(record, dict)
    ]

    if len(ids) != len(set(ids)):
        errors.append("Duplicate gate IDs detected")

    if set(ids) != REQUIRED_GATES:
        errors.append("Ledger must contain exactly the 13 required gates")

    required_fields = {
        "gate_id", "status", "evidence_refs", "commit_sha",
        "reviewer", "reviewed_at", "decision_notes"
    }

    for record in records:
        if not isinstance(record, dict):
            errors.append("Every record must be an object")
            continue

        gate_id = record.get("gate_id", "UNKNOWN")
        missing_fields = required_fields - set(record)
        if missing_fields:
            errors.append(
                f"{gate_id}: missing fields {sorted(missing_fields)}"
            )
            continue

        status = record["status"]
        refs = record["evidence_refs"]

        if status not in ALLOWED_STATUSES:
            errors.append(f"{gate_id}: invalid status")
            continue

        if not isinstance(refs, list):
            errors.append(f"{gate_id}: evidence_refs must be a list")
            continue

        if any(not valid_github_url(ref) for ref in refs):
            errors.append(
                f"{gate_id}: every evidence reference must be a valid HTTPS GitHub URL"
            )

        if status == "PASS":
            if not refs:
                errors.append(f"{gate_id}: PASS requires evidence references")

            sha = record["commit_sha"]
            if not isinstance(sha, str) or not SHA_PATTERN.fullmatch(sha):
                errors.append(f"{gate_id}: PASS requires a full 40-character commit SHA")

            if not isinstance(record["reviewer"], str) or not record["reviewer"].strip():
                errors.append(f"{gate_id}: PASS requires a named reviewer")

            if not valid_timestamp(record["reviewed_at"]):
                errors.append(f"{gate_id}: PASS requires a timezone-aware review timestamp")

            if not isinstance(record["decision_notes"], str) or not record["decision_notes"].strip():
                errors.append(f"{gate_id}: PASS requires decision notes")

    return errors


def main() -> int:
    try:
        data = json.loads(LEDGER.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"LEDGER READ ERROR: {exc}")
        return 1

    errors = validate(data)

    if errors:
        print("REVIEW LEDGER VALIDATION: FAIL")
        for error in errors:
            print(f"- {error}")
        return 1

    passed = sum(
        record["status"] == "PASS"
        for record in data["records"]
    )
    unreviewed = sum(
        record["status"] == "NOT_REVIEWED"
        for record in data["records"]
    )

    print("REVIEW LEDGER VALIDATION: PASS")
    print(f"Records validated: {len(data['records'])}")
    print(f"Human-reviewed PASS records: {passed}")
    print(f"Not reviewed: {unreviewed}")
    print("This validates record structure, not evidence truth.")
    print("Benchmark freeze requires separate review and approval.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
