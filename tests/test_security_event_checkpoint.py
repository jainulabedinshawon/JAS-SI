from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.security_event_store import JsonlSecurityEventStore
from jas_si_agent.security_event_checkpoint import (
    SecurityCheckpointError,
    create_security_checkpoint,
    load_security_checkpoint,
    save_security_checkpoint,
    verify_security_checkpoint,
)


class TestSecurityEventCheckpoint(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        root = Path(self.temp_dir.name)
        self.log_path = root / "security-events.jsonl"
        self.checkpoint_path = root / "trusted-checkpoint.json"
        self.store = JsonlSecurityEventStore(self.log_path)

    def test_checkpoint_survives_reload(self) -> None:
        self.store.append({"event_type": "test_event"})

        checkpoint = create_security_checkpoint(self.store)
        save_security_checkpoint(self.checkpoint_path, checkpoint)
        restored = load_security_checkpoint(self.checkpoint_path)

        self.assertEqual(restored, checkpoint)
        self.assertTrue(verify_security_checkpoint(self.store, restored))

    def test_rejects_modified_log(self) -> None:
        self.store.append({"event_type": "original"})
        checkpoint = create_security_checkpoint(self.store)

        self.store.append({"event_type": "unexpected_extra_event"})

        self.assertFalse(
            verify_security_checkpoint(self.store, checkpoint)
        )

    def test_rejects_tampered_event_payload(self) -> None:
        self.store.append(
            {
                "event_type": "authentication_failure",
                "status_code": 401,
            }
        )

        checkpoint = create_security_checkpoint(self.store)

        original_line = self.log_path.read_text(encoding="utf-8")
        record = json.loads(original_line)

        # Tamper with event content but preserve its original hash metadata.
        record["event_type"] = "authorization_success"

        self.log_path.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )

        self.assertFalse(
            verify_security_checkpoint(self.store, checkpoint),
            "Tampered event content must fail checkpoint verification",
        )

    def test_rejects_tampered_checkpoint_hash(self) -> None:
        self.store.append(
            {
                "event_type": "authentication_failure",
                "status_code": 401,
            }
        )

        checkpoint = create_security_checkpoint(self.store)
        save_security_checkpoint(self.checkpoint_path, checkpoint)

        # Change the saved checkpoint hash without changing the event log.
        data = json.loads(
            self.checkpoint_path.read_text(encoding="utf-8")
        )

        data["last_hash"] = (
            "0" * 64
            if checkpoint.last_hash != "0" * 64
            else "1" * 64
        )

        self.checkpoint_path.write_text(
            json.dumps(data, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )

        tampered_checkpoint = load_security_checkpoint(
            self.checkpoint_path
        )

        self.assertFalse(
            verify_security_checkpoint(self.store, tampered_checkpoint),
            "A checkpoint hash mismatch must fail verification",
        )

    def test_rejects_older_checkpoint_after_new_event(self) -> None:
        self.store.append(
            {
                "event_type": "authentication_failure",
                "status_code": 401,
            }
        )

        older_checkpoint = create_security_checkpoint(self.store)

        # A later event advances the log beyond the saved checkpoint.
        self.store.append(
            {
                "event_type": "authorization_failure",
                "status_code": 403,
            }
        )

        # Simulate restoring the older checkpoint.
        save_security_checkpoint(
            self.checkpoint_path,
            older_checkpoint,
        )
        restored_checkpoint = load_security_checkpoint(
            self.checkpoint_path
        )

        self.assertFalse(
            verify_security_checkpoint(self.store, restored_checkpoint),
            "An older checkpoint must not validate a newer event log",
        )

    def test_rejects_invalid_checkpoint_json(self) -> None:
        self.checkpoint_path.write_text(
            '{"event_count": true, "last_hash": "bad"}',
            encoding="utf-8",
        )

        with self.assertRaises(SecurityCheckpointError):
            load_security_checkpoint(self.checkpoint_path)

    def test_rejects_extra_checkpoint_fields(self) -> None:
        self.checkpoint_path.write_text(
            '{"event_count": 1, "last_hash": "'
            + "a" * 64
            + '", "extra": true}',
            encoding="utf-8",
        )

        with self.assertRaises(SecurityCheckpointError):
            load_security_checkpoint(self.checkpoint_path)

    def test_rejects_symlink_checkpoint(self) -> None:
        target = Path(self.temp_dir.name) / "target.json"
        target.write_text("{}", encoding="utf-8")

        try:
            self.checkpoint_path.symlink_to(target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"Symlinks unavailable: {exc}")

        with self.assertRaises(SecurityCheckpointError):
            load_security_checkpoint(self.checkpoint_path)


if __name__ == "__main__":
    unittest.main()
