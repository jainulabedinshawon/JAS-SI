
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "validate_review_packets.py"
)

SPEC = importlib.util.spec_from_file_location(
    "validate_review_packets", SCRIPT_PATH
)
assert SPEC is not None
assert SPEC.loader is not None

MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReviewPacketValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        self.criteria_path = self.root / "review_criteria.json"
        self.packets_path = self.root / "evidence_review_packets.json"

        criteria_records = []
        packet_records = []

        for i in range(13):
            gate_id = f"G{i}"

            criteria_records.append({
                "gate_id": gate_id,
                "required_evidence": ["Example evidence"],
                "review_checks": ["Example check"],
            })

            packet_records.append({
                "gate_id": gate_id,
                "review_status": "NOT_REVIEWED",
                "gate_approval": "NOT_GRANTED",
                "human_review_required": True,
                "candidate_files": [],
                "required_evidence": [{
                    "requirement": "Example evidence",
                    "evidence_url": None,
                    "workflow_run_id": None,
                    "commit_sha": None,
                    "artifact_name": None,
                    "review_result": "NOT_REVIEWED",
                    "reviewer_notes": "",
                }],
                "review_checks": [{
                    "check": "Example check",
                    "result": "NOT_REVIEWED",
                    "notes": "",
                }],
                "review_decision": {
                    "reviewer": None,
                    "reviewed_at": None,
                    "decision_notes": "",
                },
            })

        criteria = {"gates": criteria_records}

        packets = {
            "protocol": "JAS-SI-V0.1-EVIDENCE-REVIEW-PACKETS",
            "status": "REVIEW_PACKET_PREPARED",
            "benchmark_status": "DEVELOPMENT_NOT_FROZEN",
            "automatic_approval": False,
            "freeze_authorized": False,
            "gate_count": 13,
            "records": packet_records,
        }

        self.criteria_path.write_text(
            json.dumps(criteria),
            encoding="utf-8",
        )
        self.packets_path.write_text(
            json.dumps(packets),
            encoding="utf-8",
        )

        patcher_criteria = patch.object(
            MODULE, "CRITERIA_PATH", self.criteria_path
        )
        patcher_packets = patch.object(
            MODULE, "PACKETS_PATH", self.packets_path
        )

        patcher_criteria.start()
        patcher_packets.start()

        self.addCleanup(patcher_criteria.stop)
        self.addCleanup(patcher_packets.stop)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def read_packets(self) -> dict:
        return json.loads(
            self.packets_path.read_text(encoding="utf-8")
        )

    def write_packets(self, data: dict) -> None:
        self.packets_path.write_text(
            json.dumps(data),
            encoding="utf-8",
        )

    def test_valid_packets_pass(self) -> None:
        self.assertEqual(MODULE.validate(), [])

    def test_duplicate_gate_ids_fail(self) -> None:
        data = self.read_packets()
        data["records"][1]["gate_id"] = (
            data["records"][0]["gate_id"]
        )
        self.write_packets(data)

        self.assertTrue(any(
            "Duplicate packet gate ID" in error
            for error in MODULE.validate()
        ))

    def test_automatic_approval_is_rejected(self) -> None:
        data = self.read_packets()
        data["automatic_approval"] = True
        self.write_packets(data)

        self.assertTrue(any(
            "Automatic approval must remain disabled" in error
            for error in MODULE.validate()
        ))

    def test_freeze_authorization_is_rejected(self) -> None:
        data = self.read_packets()
        data["freeze_authorized"] = True
        self.write_packets(data)

        self.assertTrue(any(
            "Freeze authorization must remain disabled" in error
            for error in MODULE.validate()
        ))

    def test_gate_approval_must_remain_not_granted(self) -> None:
        data = self.read_packets()
        data["records"][0]["gate_approval"] = "PASS"
        self.write_packets(data)

        self.assertTrue(any(
            "gate approval must remain NOT_GRANTED" in error
            for error in MODULE.validate()
        ))

    def test_modified_evidence_requirement_is_rejected(self) -> None:
        data = self.read_packets()
        data["records"][0]["required_evidence"][0]["requirement"] = (
            "Requirement changed without criteria approval"
        )
        self.write_packets(data)

        self.assertTrue(any(
            "packet evidence requirements differ from criteria" in error
            for error in MODULE.validate()
        ))

    def test_modified_review_check_is_rejected(self) -> None:
        data = self.read_packets()
        data["records"][0]["review_checks"][0]["check"] = (
            "Unapproved review check"
        )
        self.write_packets(data)

        self.assertTrue(any(
            "packet review checks differ from criteria" in error
            for error in MODULE.validate()
        ))


if __name__ == "__main__":
    unittest.main()
