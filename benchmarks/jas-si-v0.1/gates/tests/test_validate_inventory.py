
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

GATES_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GATES_DIR))

from validate_evidence_inventory import (  # noqa: E402
    EXPECTED_GATES,
    validate_inventory,
)


def make_report() -> dict:
    records = [
        {
            "gate_id": gate_id,
            "status": "CANDIDATES_FOUND",
            "candidate_files": ["example.txt"],
            "human_review_required": True,
            "gate_passed": False,
        }
        for gate_id in sorted(EXPECTED_GATES)
    ]

    return {
        "protocol": "JAS-SI-V0.1-EVIDENCE-INVENTORY",
        "inventory_status": "DISCOVERY_ONLY",
        "benchmark_status": "DEVELOPMENT_NOT_FROZEN",
        "repository_file_count": 1,
        "gate_count": 13,
        "records": records,
    }


class EvidenceInventoryValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_root = Path(self.temp_dir.name)
        (self.repo_root / "example.txt").write_text(
            "test fixture\n",
            encoding="utf-8",
        )
        self.report = make_report()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_valid_discovery_inventory(self) -> None:
        self.assertEqual(
            validate_inventory(self.report, self.repo_root),
            [],
        )

    def test_missing_candidate_file_is_rejected(self) -> None:
        (self.repo_root / "example.txt").unlink()

        errors = validate_inventory(self.report, self.repo_root)

        self.assertTrue(
            any("does not exist" in error for error in errors)
        )

    def test_gate_approval_is_rejected(self) -> None:
        self.report["records"][0]["gate_passed"] = True

        errors = validate_inventory(self.report, self.repo_root)

        self.assertTrue(
            any("never approve a gate" in error for error in errors)
        )

    def test_frozen_status_is_rejected(self) -> None:
        self.report["benchmark_status"] = "FROZEN"

        errors = validate_inventory(self.report, self.repo_root)

        self.assertTrue(
            any("DEVELOPMENT_NOT_FROZEN" in error for error in errors)
        )

    def test_unsafe_candidate_path_is_rejected(self) -> None:
        self.report["records"][0]["candidate_files"] = [
            "../outside.txt"
        ]

        errors = validate_inventory(self.report, self.repo_root)

        self.assertTrue(
            any("unsafe candidate path" in error for error in errors)
        )


if __name__ == "__main__":
    unittest.main()
