from __future__ import annotations

import fcntl
import json
import multiprocessing
import os
import sys
import tempfile
import threading
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


def _append_events_from_process(
    path: str,
    writer_id: int,
    count: int,
) -> None:
    store = JsonlSecurityEventStore(path)

    for sequence in range(count):
        store.append(
            {
                "event_type": "concurrent_write_test",
                "writer_id": writer_id,
                "sequence": sequence,
            }
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

    def test_concurrent_process_writes_remain_valid_jsonl(self) -> None:
        writer_count = 4
        events_per_writer = 25

        processes = [
            multiprocessing.Process(
                target=_append_events_from_process,
                args=(
                    str(self.path),
                    writer_id,
                    events_per_writer,
                ),
            )
            for writer_id in range(writer_count)
        ]

        for process in processes:
            process.start()

        for process in processes:
            process.join(timeout=30)

        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join()
                self.fail("Concurrent writer process timed out")

            self.assertEqual(process.exitcode, 0)

        events = self.store.load_events()

        self.assertEqual(
            len(events),
            writer_count * events_per_writer,
        )

        observed = {
            (event["writer_id"], event["sequence"])
            for event in events
        }

        expected = {
            (writer_id, sequence)
            for writer_id in range(writer_count)
            for sequence in range(events_per_writer)
        }

        self.assertEqual(observed, expected)

    def test_reader_waits_for_exclusive_writer_lock(self) -> None:
        self.store.append({"event_type": "lock_test"})

        fd = os.open(self.path, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)

        started = threading.Event()
        finished = threading.Event()
        result = []

        def read_events() -> None:
            started.set()
            result.extend(self.store.load_events())
            finished.set()

        reader = threading.Thread(target=read_events)
        reader.start()
        self.addCleanup(reader.join, 5)

        self.assertTrue(started.wait(timeout=2))

        try:
            self.assertFalse(
                finished.wait(timeout=0.2),
                "Reader should wait while the exclusive lock is held",
            )
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)

        reader.join(timeout=5)

        self.assertFalse(reader.is_alive())
        self.assertTrue(finished.is_set())
        self.assertEqual(
            result,
            [{"event_type": "lock_test"}],
        )

    def test_new_events_have_valid_hash_chain(self) -> None:
        first = {"event_type": "first"}
        second = {"event_type": "second"}

        self.store.append(first)
        self.store.append(second)

        report = self.store.verify_integrity()
        self.assertTrue(report["valid"])
        self.assertEqual(report["verified_event_count"], 2)
        self.assertEqual(report["legacy_event_count"], 0)
        self.assertEqual(self.store.load_events(), (first, second))

    def test_tampered_event_is_rejected(self) -> None:
        self.store.append({"event_type": "original"})

        lines = self.path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["event_type"] = "tampered"
        self.path.write_text(
            json.dumps(record, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(SecurityEventStoreError):
            self.store.verify_integrity()

    def test_reordered_chain_is_rejected(self) -> None:
        self.store.append({"event_type": "first"})
        self.store.append({"event_type": "second"})

        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text(
            "\n".join(reversed(lines)) + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(SecurityEventStoreError):
            self.store.load_events()

    def test_legacy_events_are_reported_separately(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            '{"event_type":"legacy"}\n',
            encoding="utf-8",
        )

        self.store.append({"event_type": "new"})

        report = self.store.verify_integrity()
        self.assertTrue(report["valid"])
        self.assertEqual(report["legacy_event_count"], 1)
        self.assertEqual(report["verified_event_count"], 1)
        self.assertEqual(
            self.store.load_events(),
            ({"event_type": "legacy"}, {"event_type": "new"}),
        )


if __name__ == "__main__":
    unittest.main()
