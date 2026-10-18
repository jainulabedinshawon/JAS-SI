from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
FIXTURE_PATH = ROOT / "fixtures" / "p1_tasks.json"
MANIFEST_PATH = ROOT / "fixtures" / "fixture_manifest.json"


def fail(message: str) -> None:
    raise SystemExit(f"FIXTURE CONTRACT: FAIL — {message}")


def main() -> int:
    if not FIXTURE_PATH.is_file():
        fail(f"Missing fixture: {FIXTURE_PATH}")

    if not MANIFEST_PATH.is_file():
        fail(f"Missing manifest: {MANIFEST_PATH}")

    try:
        fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        manifest = json.loads(
            MANIFEST_PATH.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"Cannot read JSON: {exc}")

    if not isinstance(fixture, list) or not fixture:
        fail("Fixture must be a non-empty JSON array")

    if manifest.get("manifest_schema") != "jas-si-fixture-contract-0.1":
        fail("Unexpected manifest schema")

    if manifest.get("benchmark_id") != "jas-si-v0.1":
        fail("Unexpected benchmark ID")

    if manifest.get("condition") != "P1_ORACLE":
        fail("Unexpected condition")

    if manifest.get("status") != "development":
        fail("This gate only accepts development status")

    if manifest.get("benchmark_frozen") is not False:
        fail("Development manifest must not claim benchmark freeze")

    if manifest.get("fixture_file") != FIXTURE_PATH.name:
        fail("Manifest fixture filename does not match")

    actual_sha256 = hashlib.sha256(
        FIXTURE_PATH.read_bytes()
    ).hexdigest()

    expected_sha256 = manifest.get("fixture_sha256")

    if actual_sha256 != expected_sha256:
        fail(
            "Fixture SHA-256 mismatch. "
            f"Expected {expected_sha256}; got {actual_sha256}"
        )

    declared_count = manifest.get("task_count")

    if declared_count != len(fixture):
        fail(
            f"Task count mismatch: manifest={declared_count}, "
            f"fixture={len(fixture)}"
        )

    declared_tasks = manifest.get("tasks")

    if not isinstance(declared_tasks, list):
        fail("Manifest tasks must be a JSON array")

    fixture_ids = []
    for task in fixture:
        if not isinstance(task, dict):
            fail("Every fixture task must be an object")

        task_id = task.get("task_id")
        expected = task.get("ground_truth", {}).get(
            "expected_outcome"
        )

        if not isinstance(task_id, str) or not task_id:
            fail("Every fixture task needs a task_id")

        if not isinstance(expected, str) or not expected:
            fail(f"{task_id}: missing expected_outcome")

        fixture_ids.append(task_id)

    if len(fixture_ids) != len(set(fixture_ids)):
        fail("Duplicate task IDs in fixture")

    manifest_ids = []
    for task in declared_tasks:
        if not isinstance(task, dict):
            fail("Every manifest task must be an object")

        task_id = task.get("task_id")
        expected = task.get("expected_outcome")

        if not isinstance(task_id, str) or not task_id:
            fail("Every manifest task needs a task_id")

        if not isinstance(expected, str) or not expected:
            fail(f"{task_id}: missing expected_outcome")

        manifest_ids.append(task_id)

    if fixture_ids != manifest_ids:
        fail("Fixture task IDs/order differ from manifest")

    for fixture_task, manifest_task in zip(fixture, declared_tasks):
        task_id = fixture_task["task_id"]
        fixture_expected = fixture_task["ground_truth"][
            "expected_outcome"
        ]
        manifest_expected = manifest_task["expected_outcome"]

        if fixture_expected != manifest_expected:
            fail(f"{task_id}: expected outcome differs from manifest")

    print("Fixture contract: PASS")
    print(f"Fixture: {FIXTURE_PATH.name}")
    print(f"Task count: {len(fixture)}")
    print(f"SHA-256: {actual_sha256}")
    print("Benchmark status: DEVELOPMENT — NOT FROZEN")

    return 0


if __name__ == "__main__":
    sys.exit(main())
