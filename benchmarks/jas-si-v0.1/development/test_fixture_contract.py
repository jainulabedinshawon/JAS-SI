
from __future__ import annotations

import json
import unittest
from pathlib import Path

from validate_fixture_contract import validate_contract


FIXTURE_DIR = Path(__file__).resolve().parent


class FixtureContractTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(
            (FIXTURE_DIR / "fixture_manifest.json").read_text(
                encoding="utf-8"
            )
        )
        cls.ground_truth = json.loads(
            (FIXTURE_DIR / "ground_truth.json").read_text(
                encoding="utf-8"
            )
        )

    def test_valid_contract_is_accepted(self):
        errors = validate_contract(
            self.manifest,
            self.ground_truth,
        )
        self.assertEqual(errors, [])

    def test_missing_manifest_field_is_rejected(self):
        manifest = dict(self.manifest)
        manifest.pop("task_id")

        errors = validate_contract(manifest, self.ground_truth)

        self.assertTrue(any("missing fields" in e for e in errors))

    def test_frozen_benchmark_flag_is_rejected(self):
        manifest = dict(self.manifest)
        manifest["benchmark_content_frozen"] = True

        errors = validate_contract(manifest, self.ground_truth)

        self.assertTrue(any("must not be frozen" in e for e in errors))

    def test_agent_report_cannot_be_authoritative(self):
        truth = dict(self.ground_truth)
        truth["agent_report_authority"] = True

        errors = validate_contract(self.manifest, truth)

        self.assertTrue(
            any("must not be authoritative" in e for e in errors)
        )

    def test_wrong_expected_content_is_rejected(self):
        truth = dict(self.ground_truth)
        truth["expected_state"] = dict(
            self.ground_truth["expected_state"]
        )
        truth["expected_state"]["required_content"] = "WRONG\n"

        errors = validate_contract(self.manifest, truth)

        self.assertTrue(
            any("expected_state contract" in e for e in errors)
        )

    def test_non_object_input_is_rejected(self):
        errors = validate_contract([], self.ground_truth)

        self.assertTrue(
            any("Manifest must be a JSON object" in e for e in errors)
        )


if __name__ == "__main__":
    unittest.main()
