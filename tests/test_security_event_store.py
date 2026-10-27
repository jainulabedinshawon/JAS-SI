
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

from jas_si_agent.security_event_store import (  # noqa: E402
    JsonlSecurityEventStore,
    SecurityEventStoreError,
)


class TestJsonlSecurityEventStore(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.path = (
            Path(self.temp_dir.name) / "audit" / "security-events.jsonl"
        )
        self.store = JsonlSecurityEventStore(self.path)

    def test_missing_file_returns_empty_tuple(self) -> None:
        self.assertEqual(self.store.load_events(), ())

    def test_append_and_reload_events(self) -> None:
        first = {
            "event_type": "authentication_failure",
            "status_code": 401,
            "reason_code": "missing_api_key",
        }
        second = {
            "event_type": "authorization_evaluated",
            "status_code": 200,
            "allowed": False,
        }

        self.store.append(first)
        self.store.append(second)

        self.assertEqual(
            self.store.load_events(),
            (first, second),
        )

    def test_data_survives_store_recreation(self) -> None:
        event = {
            "event_type": "rate_limit_exceeded",
            "status_code": 429,
        }
        self.store.append(event)

        reopened_store = JsonlSecurityEventStore(self.path)

        self.assertEqual(reopened_store.load_events(), (event,))

    def test_each_event_is_one_json_line(self) -> None:
        self.store.append({"event_type": "one"})
        self.store.append({"event_type": "two"})

        lines = self.path.read_text(encoding="utf-8").splitlines()

        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["event_type"], "one")
        self.assertEqual(json.loads(lines[1])["event_type"], "two")

    def test_rejects_non_mapping_event(self) -> None:
        with self.assertRaises(SecurityEventStoreError):
            self.store.append(["not", "an", "event"])  # type: ignore[arg-type]

    def test_rejects_non_json_values(self) -> None:
        with self.assertRaises(SecurityEventStoreError):
            self.store.append({"invalid": object()})

    def test_rejects_nan(self) -> None:
        with self.assertRaises(SecurityEventStoreError):
            self.store.append({"value": float("nan")})

    def test_rejects_oversized_event(self) -> None:
        with self.assertRaises(SecurityEventStoreError):
            self.store.append({"data": "x" * (65 * 1024)})

    def test_rejects_malformed_json_on_read(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("{broken json}\n", encoding="utf-8")

        with self.assertRaises(SecurityEventStoreError):
            self.store.load_events()

    def test_rejects_blank_line_on_read(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("\n", encoding="utf-8")

        with self.assertRaises(SecurityEventStoreError):
            self.store.load_events()

    def test_rejects_symlink(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        target = Path(self.temp_dir.name) / "target.jsonl"
        target.write_text("", encoding="utf-8")

        try:
            self.path.symlink_to(target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"Symlinks unavailable: {exc}")

        with self.assertRaises(SecurityEventStoreError):
            self.store.append({"event_type": "test"})


if __name__ == "__main__":
    unittest.main()
