from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
RUNNER_PATH = HERE / "run_p10.py"

spec = importlib.util.spec_from_file_location("p10_runner", RUNNER_PATH)
p10_runner = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(p10_runner)


class P10HeldoutVFLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with p10_runner.FIXTURE.open("r", encoding="utf-8") as handle:
            cls.fixture = json.load(handle)

    def test_exactly_ten_unique_seeds(self):
        seeds = self.fixture["seeds"]
        self.assertEqual(len(seeds), 10)
        self.assertEqual(
            {item["seed"] for item in seeds},
            set(range(1, 11)),
        )

    def test_training_and_heldout_evidence_are_disjoint(self):
        training = {
            item["training_evidence_id"]
            for item in self.fixture["seeds"]
        }
        heldout = {
            item["heldout_evidence_id"]
            for item in self.fixture["seeds"]
        }
        self.assertTrue(training.isdisjoint(heldout))

    def test_all_feedback_is_verified(self):
        for seed in self.fixture["seeds"]:
            with self.subTest(seed=seed["seed"]):
                self.assertIs(seed["verified_failure_feedback"], True)

    def test_false_success_rate_uses_correct_denominator(self):
        self.assertAlmostEqual(
            p10_runner.false_success_rate(7, 3), 0.30
        )
        self.assertAlmostEqual(
            p10_runner.false_success_rate(9, 1), 0.10
        )

    def test_zero_denominator_is_undefined(self):
        self.assertIsNone(p10_runner.false_success_rate(0, 0))

    def test_synthetic_fixture_delta_is_not_an_empirical_threshold(self):
        results = [
            p10_runner.calculate_seed(seed)
            for seed in self.fixture["seeds"]
        ]
        improvements = [
            result["absolute_fsr_improvement"]
            for result in results
        ]
        self.assertTrue(all(value is not None for value in improvements))
        self.assertAlmostEqual(sum(improvements) / len(improvements), 0.20)
        self.assertGreaterEqual(
            sum(improvements) / len(improvements),
            p10_runner.DELTA,
        )

    def test_synthetic_fixture_cannot_pass_empirical_release_gate(self):
        result = {
            "evidence_type": "SYNTHETIC_DEVELOPMENT_FIXTURE",
            "independent_empirical_replications_established": False,
            "all_feedback_verified": True,
            "training_heldout_evidence_overlap_count": 0,
            "seed_count": 10,
            "required_seed_count": 10,
            "empirical_threshold_met": None,
        }
        self.assertFalse(p10_runner.empirical_release_gate_passed(result))

    def test_empirical_gate_rejects_missing_or_unknown_evidence_type(self):
        otherwise_valid = {
            "independent_empirical_replications_established": True,
            "all_feedback_verified": True,
            "training_heldout_evidence_overlap_count": 0,
            "seed_count": 10,
            "required_seed_count": 10,
            "empirical_threshold_met": True,
        }
        self.assertFalse(
            p10_runner.empirical_release_gate_passed(otherwise_valid)
        )
        self.assertFalse(
            p10_runner.empirical_release_gate_passed(
                dict(otherwise_valid, evidence_type="UNREVIEWED_SOURCE")
            )
        )

    def test_empirical_gate_requires_explicit_real_world_evidence_type(self):
        otherwise_valid = {
            "evidence_type": "INDEPENDENT_REAL_WORLD_EMPIRICAL_DATA",
            "independent_empirical_replications_established": True,
            "all_feedback_verified": True,
            "training_heldout_evidence_overlap_count": 0,
            "seed_count": 10,
            "required_seed_count": 10,
            "empirical_threshold_met": True,
        }
        self.assertTrue(
            p10_runner.empirical_release_gate_passed(otherwise_valid)
        )

    def test_identical_seed_outcomes_are_counted_as_one_signature(self):
        signatures = {
            (
                seed["baseline_true_success"],
                seed["baseline_false_success"],
                seed["post_feedback_true_success"],
                seed["post_feedback_false_success"],
            )
            for seed in self.fixture["seeds"]
        }
        self.assertEqual(len(signatures), 1)

    def test_each_seed_has_non_overlapping_evidence_ids(self):
        for seed in self.fixture["seeds"]:
            with self.subTest(seed=seed["seed"]):
                self.assertNotEqual(
                    seed["training_evidence_id"],
                    seed["heldout_evidence_id"],
                )

    def test_apparatus_gate_requires_fixture_threshold(self):
        valid = {
            "all_feedback_verified": True,
            "training_heldout_evidence_overlap_count": 0,
            "seed_count": 10,
            "required_seed_count": 10,
            "fixture_practical_threshold_met": True,
        }
        self.assertTrue(p10_runner.apparatus_gate_passed(valid))

        below_threshold = dict(valid, fixture_practical_threshold_met=False)
        self.assertFalse(p10_runner.apparatus_gate_passed(below_threshold))

        missing_threshold = dict(valid)
        missing_threshold.pop("fixture_practical_threshold_met")
        self.assertFalse(p10_runner.apparatus_gate_passed(missing_threshold))

    def test_apparatus_gate_requires_every_integrity_condition(self):
        valid = {
            "all_feedback_verified": True,
            "training_heldout_evidence_overlap_count": 0,
            "seed_count": 10,
            "required_seed_count": 10,
            "practical_threshold_met": True,
        }
        for key, value in (
            ("all_feedback_verified", False),
            ("training_heldout_evidence_overlap_count", 1),
            ("seed_count", 9),
            ("required_seed_count", 9),
        ):
            with self.subTest(field=key):
                self.assertFalse(
                    p10_runner.apparatus_gate_passed(dict(valid, **{key: value}))
                )


if __name__ == "__main__":
    unittest.main()
