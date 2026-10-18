
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
                self.assertIs(
                    seed["verified_failure_feedback"], True
                )

    def test_false_success_rate_uses_correct_denominator(self):
        self.assertAlmostEqual(
            p10_runner.false_success_rate(7, 3), 0.30
        )
        self.assertAlmostEqual(
            p10_runner.false_success_rate(9, 1), 0.10
        )

    def test_zero_denominator_is_undefined(self):
        self.assertIsNone(p10_runner.false_success_rate(0, 0))

    def test_synthetic_heldout_improvement_meets_threshold(self):
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

    def test_each_seed_has_non_overlapping_evidence_ids(self):
        for seed in self.fixture["seeds"]:
            with self.subTest(seed=seed["seed"]):
                self.assertNotEqual(
                    seed["training_evidence_id"],
                    seed["heldout_evidence_id"],
                )


if __name__ == "__main__":
    unittest.main()
