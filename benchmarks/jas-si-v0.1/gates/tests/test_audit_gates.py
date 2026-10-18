
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

GATES_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = GATES_DIR / "audit_gates.py"

spec = importlib.util.spec_from_file_location("audit_gates", MODULE_PATH)
audit_gates = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(audit_gates)


class EvidenceGateAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(
            (GATES_DIR / "evidence_registry.json").read_text(
                encoding="utf-8"
            )
        )

    def test_registry_contains_all_required_gates(self):
        self.assertEqual(audit_gates.validate_registry(self.data), [])

    def test_unreviewed_registry_is_not_freeze_ready(self):
        unpassed = [
            gate for gate in self.data["gates"]
            if gate["status"] != "PASS"
        ]
        self.assertTrue(unpassed)

    def test_pass_without_evidence_reference_is_rejected(self):
        data = json.loads(json.dumps(self.data))
        data["gates"][0]["status"] = "PASS"
        data["gates"][0]["evidence_refs"] = []
        errors = audit_gates.validate_registry(data)
        self.assertTrue(any("PASS requires evidence_refs" in e for e in errors))

    def test_missing_required_gate_is_rejected(self):
        data = json.loads(json.dumps(self.data))
        data["gates"] = [
            gate for gate in data["gates"]
            if gate["gate_id"] != "P7"
        ]
        errors = audit_gates.validate_registry(data)
        self.assertTrue(any("missing required gates" in e for e in errors))

    def test_duplicate_gate_id_is_rejected(self):
        data = json.loads(json.dumps(self.data))
        data["gates"].append(dict(data["gates"][0]))
        errors = audit_gates.validate_registry(data)
        self.assertTrue(any("duplicate gate_id" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
