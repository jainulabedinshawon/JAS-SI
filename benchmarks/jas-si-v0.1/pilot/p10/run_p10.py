
from __future__ import annotations

import json
from pathlib import Path
from statistics import mean
from typing import Any

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "p10_heldout_cases.json"
RESULTS_DIR = ROOT.parent / "results"
OUTPUT = RESULTS_DIR / "p10_heldout_vfl_result.json"

REQUIRED_SEEDS = 10
DELTA = 0.10


def false_success_rate(true_success: int, false_success: int) -> float | None:
    """FSR denominator is TRUE_SUCCESS + FALSE_SUCCESS."""
    denominator = true_success + false_success
    if denominator == 0:
        return None
    return false_success / denominator


def validate_seed(seed: dict[str, Any]) -> None:
    count_fields = (
        "baseline_true_success",
        "baseline_false_success",
        "post_feedback_true_success",
        "post_feedback_false_success",
    )

    for field in count_fields:
        value = seed[field]
        if type(value) is not int or value < 0:
            raise ValueError(
                f"Seed {seed['seed']}: {field} must be a non-negative integer."
            )

    if seed["verified_failure_feedback"] is not True:
        raise ValueError(
            f"Seed {seed['seed']}: feedback must be independently verified."
        )

    if not seed["training_evidence_id"] or not seed["heldout_evidence_id"]:
        raise ValueError(
            f"Seed {seed['seed']}: evidence IDs must not be empty."
        )

    if seed["training_evidence_id"] == seed["heldout_evidence_id"]:
        raise ValueError(
            f"Seed {seed['seed']}: training and held-out evidence overlap."
        )


def calculate_seed(seed: dict[str, Any]) -> dict[str, Any]:
    validate_seed(seed)

    baseline = false_success_rate(
        seed["baseline_true_success"],
        seed["baseline_false_success"],
    )
    post_feedback = false_success_rate(
        seed["post_feedback_true_success"],
        seed["post_feedback_false_success"],
    )

    if baseline is None or post_feedback is None:
        improvement = None
    else:
        improvement = baseline - post_feedback

    return {
        "seed": seed["seed"],
        "training_evidence_id": seed["training_evidence_id"],
        "heldout_evidence_id": seed["heldout_evidence_id"],
        "baseline_false_success_rate": baseline,
        "post_feedback_false_success_rate": post_feedback,
        "absolute_fsr_improvement": improvement,
        "feedback_verified": seed["verified_failure_feedback"],
    }


def main() -> int:
    with FIXTURE.open("r", encoding="utf-8") as handle:
        fixture = json.load(handle)

    seeds = fixture["seeds"]
    seed_ids = [item["seed"] for item in seeds]

    if len(seeds) != REQUIRED_SEEDS:
        raise ValueError(f"P10 requires exactly {REQUIRED_SEEDS} seeds.")

    if len(set(seed_ids)) != REQUIRED_SEEDS:
        raise ValueError("P10 seed IDs must be unique.")

    if set(seed_ids) != set(range(1, REQUIRED_SEEDS + 1)):
        raise ValueError("Expected seed IDs 1 through 10.")

    training_ids = set()
    heldout_ids = set()

    for item in seeds:
        validate_seed(item)
        training_ids.add(item["training_evidence_id"])
        heldout_ids.add(item["heldout_evidence_id"])

    overlap = training_ids & heldout_ids
    if overlap:
        raise ValueError(
            f"Training/held-out evidence leakage detected: {sorted(overlap)}"
        )

    per_seed = [calculate_seed(item) for item in seeds]
    improvements = [
        item["absolute_fsr_improvement"] for item in per_seed
    ]

    if any(value is None for value in improvements):
        mean_improvement = None
        threshold_met = False
    else:
        mean_improvement = mean(improvements)
        threshold_met = mean_improvement >= DELTA

    baseline_rates = [
        item["baseline_false_success_rate"] for item in per_seed
    ]
    post_rates = [
        item["post_feedback_false_success_rate"] for item in per_seed
    ]

    result = {
        "protocol": fixture["protocol"],
        "condition": "P10_HELDOUT_VERIFIED_FAILURE_LEARNING",
        "evidence_type": fixture["evidence_type"],
        "seed_count": len(seeds),
        "required_seed_count": REQUIRED_SEEDS,
        "practical_threshold_delta": fixture["practical_threshold_delta"],
        "mean_baseline_false_success_rate": mean(baseline_rates),
        "mean_post_feedback_false_success_rate": mean(post_rates),
        "mean_absolute_fsr_improvement": mean_improvement,
        "practical_threshold_met": threshold_met,
        "training_heldout_evidence_overlap_count": len(overlap),
        "all_feedback_verified": all(
            item["verified_failure_feedback"] is True for item in seeds
        ),
        "per_seed_results": per_seed,
        "limitations": [
            "Synthetic development fixture only.",
            "The fixture encodes outcomes; it does not train a real agent.",
            "No independent external evaluator is used in this apparatus.",
            "Threshold attainment is not statistical significance.",
            "No claim of real-world verified-failure learning is established."
        ],
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(
            result,
            handle,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        handle.write("\n")

    print(json.dumps(result, indent=2, sort_keys=True))

    return 0 if (
        result["all_feedback_verified"]
        and result["training_heldout_evidence_overlap_count"] == 0
        and result["seed_count"] == REQUIRED_SEEDS
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
