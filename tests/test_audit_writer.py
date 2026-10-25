from __future__ import annotations

import sys
import tempfile
import threading
import unittest
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
from jas_si_agent.audit_writer import AuditWriter  # noqa: E402
from jas_si_agent.authorization import (  # noqa: E402
    ActionRequest,
    AuthorizationDecision,
)
from jas_si_agent.verification import (  # noqa: E402
    VerificationResult,
    VerificationStatus,
)


class TestAuditWriter(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        path = Path(self.temp_dir.name) / "audit" / "events.jsonl"
        self.store = JsonlAuditStore(path)
        self.writer = AuditWriter(self.store)

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

    def test_writes_and_reloads_valid_record(self) -> None:
        record = self.make_record()
        self.writer.write(record)
        self.assertEqual(self.writer.load_records(), (record,))

    def test_append_alias_writes_record(self) -> None:
        record = self.make_record()
        self.writer.append(record)
        self.assertEqual(self.store.load_records(), (record,))

    def test_rejects_non_audit_record(self) -> None:
        with self.assertRaises(AuditStoreError):
            self.writer.write({"action_id": "fake"})  # type: ignore[arg-type]

        self.assertEqual(self.store.load_records(), ())

    def test_rejects_tampered_record(self) -> None:
        from dataclasses import replace

        record = self.make_record()
        altered = replace(
            record,
            authorization_reason="TAMPERED",
        )

        with self.assertRaises(AuditStoreError):
            self.writer.write(altered)

        self.assertEqual(self.store.load_records(), ())

    def test_storage_failure_propagates(self) -> None:
        record = self.make_record()

        # A directory at the intended file path forces the store's append
        # operation to fail instead of creating a regular audit file.
        self.store.path.parent.mkdir(parents=True, exist_ok=True)
        self.store.path.mkdir()

        with self.assertRaises(AuditStoreError):
            self.writer.write(record)

    def test_duplicate_concurrent_write_does_not_duplicate_record(self) -> None:
        record = self.make_record()
        barrier = threading.Barrier(3)
        successes: list[bool] = []
        errors: list[Exception] = []
        result_lock = threading.Lock()

        def attempt_write() -> None:
            barrier.wait()
            try:
                self.writer.write(record)
                result = True
            except AuditStoreError as exc:
                with result_lock:
                    errors.append(exc)
                result = False

            with result_lock:
                successes.append(result)

        threads = [
            threading.Thread(target=attempt_write),
            threading.Thread(target=attempt_write),
        ]

        for thread in threads:
            thread.start()

        barrier.wait()

        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(sum(successes), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(self.store.load_records(), (record,))

    def test_invalid_write_does_not_create_a_record(self) -> None:
        from dataclasses import replace

        record = self.make_record()
        altered = replace(
            record,
            authorization_reason="TAMPERED",
        )

        with self.assertRaises(AuditStoreError):
            self.writer.write(altered)

        self.assertEqual(self.writer.load_records(), ())


if __name__ == "__main__":
    unittest.main()
