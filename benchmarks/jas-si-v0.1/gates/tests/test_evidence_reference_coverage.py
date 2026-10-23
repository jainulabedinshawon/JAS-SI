
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


GATES_DIR = Path(__file__).resolve().parents[1]
SCRIPT_PATH = GATES_DIR / "build_evidence_reference_coverage.py"

SPEC = importlib.util.spec_from_file_location(
    "evidence_reference_coverage",
    SCRIPT_PATH,
)

if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Cannot load evidence coverage script.")

coverage = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = coverage
SPEC.loader.exec_module(coverage)


class EvidenceReferenceCoverageTests(unittest.TestCase):

    def test_current_report_is_discovery_only(self):
        report = coverage.build_report()

        self.assertEqual(
            report["protocol"],
            "JAS-SI-V0.1-EVIDENCE-REFERENCE-COVERAGE",
        )
        self.assertEqual(
            report["report_status"],
            "COVERAGE_AUDIT_ONLY",
        )
        self.assertEqual(
            report["benchmark_status"],
            "DEVELOPMENT_NOT_FROZEN",
        )
        self.assertEqual(report["gate_count"], 13)

    def test_no_gate_is_automatically_approved(self):
        report = coverage.build_report()

        self.assertIs(
            report["automatic_approval"],
            False,
        )
        self.assertIs(
            report["freeze_authorized"],
            False,
        )

        for record in report["records"]:
            self.assertIs(
                record["gate_passed"],
                False,
                msg=f"{record['gate_id']} must not auto-pass",
            )
            self.assertEqual(
                record["gate_approval"],
                "NOT_GRANTED",
            )
            self.assertIs(
                record["human_review_required"],
                True,
            )

    def test_review_criteria_status_is_checked_correctly(self):
        report = coverage.build_report()

        self.assertEqual(report["gate_count"], 13)

        criteria_path = GATES_DIR / "review_criteria.json"
        criteria = json.loads(
            criteria_path.read_text(encoding="utf-8")
        )

        self.assertEqual(
            criteria.get("status"),
            "REVIEW_PLAN_ONLY",
        )
        self.assertNotEqual(
            criteria.get("status"),
            "DEVELOPMENT_NOT_FROZEN",
        )

    def test_wrong_benchmark_status_is_rejected(self):
        original_registry = coverage.REGISTRY_PATH

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir) / "registry.json"

                registry = json.loads(
                    original_registry.read_text(encoding="utf-8")
                )
                registry["benchmark_status"] = "FROZEN"
                temp_path.write_text(
                    json.dumps(registry),
                    encoding="utf-8",
                )

                with patch.object(
                    coverage,
                    "REGISTRY_PATH",
                    temp_path,
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "registry must remain DEVELOPMENT_NOT_FROZEN",
                    ):
                        coverage.build_report()
        finally:
            pass


if __name__ == "__main__":
    unittest.main()
