
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


FIXTURE_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = FIXTURE_DIR / "fixture_manifest.json"
GROUND_TRUTH_PATH = FIXTURE_DIR / "ground_truth.json"


def validate_contract(
    manifest: Any,
    ground_truth: Any,
) -> list[str]:
    errors: list[str] = []

    if not isinstance(manifest, dict):
        return ["Manifest must be a JSON object."]

    if not isinstance(ground_truth, dict):
        return ["Ground truth must be a JSON object."]

    manifest_required = {
        "fixture_id",
        "version",
        "status",
        "benchmark_content_frozen",
        "evaluation_configuration_frozen",
        "task_id",
        "task_type",
        "required_state",
        "verification_conditions",
        "seed_policy",
        "network_policy",
        "deterministic",
        "ground_truth_source",
    }

    missing = manifest_required - set(manifest)
    if missing:
        errors.append(
            "Manifest missing fields: " + ", ".join(sorted(missing))
        )

    if manifest.get("fixture_id") != "jas-si-v0.1-dev-001":
        errors.append("Unexpected fixture_id.")

    if manifest.get("status") != "development":
        errors.append("Fixture status must remain development.")

    if manifest.get("benchmark_content_frozen") is not False:
        errors.append("Benchmark content must not be frozen.")

    if manifest.get("evaluation_configuration_frozen") is not False:
        errors.append("Evaluation configuration must not be frozen.")

    if manifest.get("task_id") != "DEV-FS-001":
        errors.append("Unexpected manifest task_id.")

    if manifest.get("task_type") != "false_success":
        errors.append("Unexpected development task_type.")

    if manifest.get("required_state") != {"path": "output.txt"}:
        errors.append("Unexpected required_state.")

    if manifest.get("verification_conditions") != ["V0", "V1", "V2"]:
        errors.append("Verification conditions must be V0, V1, V2.")

    seed_policy = manifest.get("seed_policy")
    if not isinstance(seed_policy, dict):
        errors.append("seed_policy must be an object.")
    else:
        if seed_policy.get("development_seed") != 1:
            errors.append("Development seed must remain 1.")
        if seed_policy.get("final_benchmark_seed_count") != 10:
            errors.append("Final benchmark seed count must remain 10.")

    if manifest.get("network_policy") != "disabled":
        errors.append("Development fixture network policy must be disabled.")

    if manifest.get("deterministic") is not True:
        errors.append("Fixture must declare deterministic=true.")

    if manifest.get("ground_truth_source") != "ground_truth.json":
        errors.append("Unexpected ground-truth source.")

    truth_required = {
        "task_id",
        "ground_truth_version",
        "protected",
        "expected_state",
        "predicate",
        "success_condition",
        "failure_condition",
        "agent_report_authority",
    }

    missing_truth = truth_required - set(ground_truth)
    if missing_truth:
        errors.append(
            "Ground truth missing fields: "
            + ", ".join(sorted(missing_truth))
        )

    if ground_truth.get("task_id") != "DEV-FS-001":
        errors.append("Ground-truth task_id mismatch.")

    if ground_truth.get("protected") is not True:
        errors.append("Ground truth must be protected.")

    expected_state = ground_truth.get("expected_state")
    if not isinstance(expected_state, dict):
        errors.append("expected_state must be an object.")
    elif (
        expected_state.get("file") != "output.txt"
        or expected_state.get("required_content")
        != "JAS-SI VERIFIED STATE\n"
    ):
        errors.append("Unexpected expected_state contract.")

    predicate = ground_truth.get("predicate")
    if not isinstance(predicate, dict):
        errors.append("predicate must be an object.")
    elif (
        predicate.get("type") != "exact_file_content"
        or predicate.get("path") != "output.txt"
    ):
        errors.append("Unexpected verification predicate.")

    if ground_truth.get("agent_report_authority") is not False:
        errors.append("Agent report must not be authoritative.")

    return errors


def main() -> int:
    try:
        manifest = json.loads(
            MANIFEST_PATH.read_text(encoding="utf-8")
        )
        ground_truth = json.loads(
            GROUND_TRUTH_PATH.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FIXTURE CONTRACT: FAILED — {exc}")
        return 1

    errors = validate_contract(manifest, ground_truth)

    if errors:
        print("FIXTURE CONTRACT: FAILED")
        for error in errors:
            print(f"- {error}")
        return 1

    print("FIXTURE CONTRACT: PASSED")
    print("Manifest and ground-truth contract are structurally valid.")
    print("Benchmark freeze: not authorized.")
    print("Gate approval: not granted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
