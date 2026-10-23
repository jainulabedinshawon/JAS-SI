
from __future__ import annotations

import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.audit_log import AuditLog  # noqa: E402
from jas_si_agent.audit_store import (  # noqa: E402
    AuditStoreError,
    JsonlAuditStore,
)
from jas_si_agent.authorization import (  # noqa: E402
    ActionRequest,
    AuthorizationDecision,
)
from jas_si_agent.verification import (  # noqa: E402
    VerificationResult,
    VerificationStatus,
)


class TestJsonlAuditStore(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.path = Path(self.temp_dir.name) / "audit" / "events.jsonl"
        self.store = JsonlAuditStore(self.path)

        self.log = AuditLog()
        self.request = ActionRequest(
            action_id="action-001",
            action_type="read_repository",
            resource="README.md",
        )
        self.decision = AuthorizationDecision(
            allowed=True,
            reason="SAFE_ACTION_POLICY_ALLOWED",
            action_id="action-001",
        )
        self.verification = VerificationResult(
            status=VerificationStatus.VERIFIED_SUCCESS,
            reason="REPORT_MATCHES_SUCCESS_EVIDENCE",
            action_id="action-001",
        )

    def make_record(self):
        return self.log.append(
            self.request,
            self.decision,
            self.verification,
            evidence_ref="evidence-001",
        )

    def test_missing_file_returns_empty_records(self) -> None:
        self.assertEqual(self.store.load_records(), ())

    def test_append_and_reload_records(self) -> None:
        first = self.make_record()
        self.store.append(first)

        second = self.make_record()
        self.store.append(second)

        loaded = self.store.load_records()
        self.assertEqual(loaded, (first, second))
        self.assertEqual(loaded[1].previous_hash, first.record_hash)

    def test_rejects_invalid_record_hash(self) -> None:
        record = self.make_record()
        altered = replace(record, authorization_reason="ALTERED")

        with self.assertRaises(AuditStoreError):
            self.store.append(altered)

        self.assertFalse(self.path.exists())

    def test_rejects_broken_chain(self) -> None:
        first = self.make_record()
        self.store.append(first)

        second = self.make_record()
        altered = replace(second, previous_hash="f" * 64)

        with self.assertRaises(AuditStoreError):
            self.store.append(altered)

    def test_rejects_tampered_file(self) -> None:
        record = self.make_record()
        self.store.append(record)

        text = self.path.read_text(encoding="utf-8")
        self.path.write_text(
            text.replace(
                "SAFE_ACTION_POLICY_ALLOWED",
                "ALTERED",
            ),
            encoding="utf-8",
        )

        with self.assertRaises(AuditStoreError):
            self.store.load_records()

    def test_rejects_malformed_json(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("{invalid json}\n", encoding="utf-8")

        with self.assertRaises(AuditStoreError):
            self.store.load_records()

    def test_rejects_blank_lines(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("\n", encoding="utf-8")

        with self.assertRaises(AuditStoreError):
            self.store.load_records()


if __name__ == "__main__":
    unittest.main()
