from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.postgres_security_event_store import (
    GENESIS_HASH,
    PostgresSecurityEventStore,
)
from jas_si_agent.security_event_store import (
    MAX_EVENT_BYTES,
    SecurityEventStoreError,
    _event_hash,
)


class FakeCursor:
    def __init__(self, last_hash=GENESIS_HASH):
        self.last_hash = last_hash
        self.calls = []
        self.next_fetchone = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, params=None):
        self.calls.append((query, params))

        if "SELECT %s::jsonb" in query:
            self.next_fetchone = (params[0].obj,)

    def fetchone(self):
        if self.next_fetchone is not None:
            result = self.next_fetchone
            self.next_fetchone = None
            return result

        return (self.last_hash,)


class FakeConnection:
    def __init__(self, cursor):
        self.fake_cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self):
        return self.fake_cursor


class TestPostgresSecurityEventStore(unittest.TestCase):

    def setUp(self):
        self.cursor = FakeCursor()
        self.connection = FakeConnection(self.cursor)

        self.psycopg = ModuleType("psycopg")
        self.psycopg.connect = lambda dsn: self.connection

        self.json_module = ModuleType("psycopg.types.json")

        class Jsonb:
            def __init__(self, value):
                self.obj = value

        self.json_module.Jsonb = Jsonb

        self.types_module = ModuleType("psycopg.types")
        self.types_module.json = self.json_module

        self.modules = {
            "psycopg": self.psycopg,
            "psycopg.types": self.types_module,
            "psycopg.types.json": self.json_module,
        }

        self.store = PostgresSecurityEventStore(
            "postgresql://test:test@localhost/test"
        )

    def test_constructor_rejects_empty_dsn(self):
        with self.assertRaises(ValueError):
            PostgresSecurityEventStore(" ")

    def test_append_delegates_atomic_write_to_database_owned_routine(self):
        event = {
            "event_type": "authorization_evaluated",
            "allowed": True,
        }

        with patch.dict(sys.modules, self.modules):
            self.store.append(event)

        self.assertEqual(len(self.cursor.calls), 1)
        query, params = self.cursor.calls[0]
        self.assertIn(
            "SELECT public.jas_si_audit_append_event(%s::jsonb)",
            query,
        )
        self.assertEqual(params[0].obj, event)
        self.assertNotIn("INSERT INTO jas_si_audit_events", query)
        self.assertNotIn("UPDATE jas_si_audit_chain_state", query)

    def test_append_uses_one_database_call_for_every_checkpoint_state(self):
        event = {"event_type": "second_event"}
        self.cursor.last_hash = "a" * 64

        with patch.dict(sys.modules, self.modules):
            self.store.append(event)

        self.assertEqual(len(self.cursor.calls), 1)
        self.assertIn("jas_si_audit_append_event", self.cursor.calls[0][0])

    def test_database_writer_failure_raises_store_error(self):
        def fail_execute(query, params=None):
            raise RuntimeError("database writer routine unavailable")

        self.cursor.execute = fail_execute
        with patch.dict(sys.modules, self.modules):
            with self.assertRaises(SecurityEventStoreError):
                self.store.append({"event_type": "test"})

    def test_rejects_non_mapping_event(self):
        with self.assertRaises(SecurityEventStoreError):
            self.store.append(["invalid"])

    def test_rejects_reserved_integrity_field(self):
        with self.assertRaises(SecurityEventStoreError):
            self.store.append({"_integrity": {}})

    def test_rejects_non_json_event(self):
        with self.assertRaises(SecurityEventStoreError):
            self.store.append({"invalid": object()})

    def test_rejects_nan(self):
        with self.assertRaises(SecurityEventStoreError):
            self.store.append({"value": float("nan")})

    def test_rejects_oversized_event(self):
        with self.assertRaises(SecurityEventStoreError):
            self.store.append({
                "data": "x" * MAX_EVENT_BYTES
            })

    def test_database_failure_raises_store_error(self):
        self.psycopg.connect = lambda dsn: (
            (_ for _ in ()).throw(RuntimeError("database unavailable"))
        )

        with patch.dict(sys.modules, self.modules):
            with self.assertRaises(SecurityEventStoreError):
                self.store.append({"event_type": "test"})


if __name__ == "__main__":
    unittest.main()
