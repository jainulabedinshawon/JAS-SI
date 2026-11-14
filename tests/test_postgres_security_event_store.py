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
)


class FakeCursor:
    def __init__(self, last_hash=GENESIS_HASH):
        self.last_hash = last_hash
        self.calls = []
        self.next_fetchone = None
        self.raise_on_execute = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, params=None):
        self.calls.append((query, params))
        if self.raise_on_execute is not None:
            raise self.raise_on_execute

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

    def test_append_delegates_to_database_owned_writer(self):
        event = {
            "event_type": "authorization_evaluated",
            "allowed": True,
        }

        with patch.dict(sys.modules, self.modules):
            self.store.append(event)

        self.assertEqual(len(self.cursor.calls), 1)
        query, params = self.cursor.calls[0]
        self.assertIn("public.jas_si_audit_append_event", query)
        self.assertEqual(params[0].obj, event)

    def test_append_in_transaction_uses_same_database_writer(self):
        event = {"event_type": "same_transaction"}
        with patch.dict(sys.modules, self.modules):
            PostgresSecurityEventStore.append_in_transaction(
                self.connection,
                event,
            )
        self.assertEqual(len(self.cursor.calls), 1)
        self.assertIn("public.jas_si_audit_append_event", self.cursor.calls[0][0])
        self.assertEqual(self.cursor.calls[0][1][0].obj, event)

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

    def test_database_writer_rejects_invalid_checkpoint(self):
        self.cursor.raise_on_execute = RuntimeError("invalid audit checkpoint")
        with patch.dict(sys.modules, self.modules):
            with self.assertRaises(SecurityEventStoreError):
                self.store.append({"event_type": "test"})

    def test_database_writer_rejects_missing_checkpoint(self):
        self.cursor.raise_on_execute = RuntimeError("audit checkpoint unavailable")
        with patch.dict(sys.modules, self.modules):
            with self.assertRaises(SecurityEventStoreError):
                self.store.append({"event_type": "test"})

    def test_database_failure_raises_store_error(self):
        self.psycopg.connect = lambda dsn: (
            (_ for _ in ()).throw(RuntimeError("database unavailable"))
        )

        with patch.dict(sys.modules, self.modules):
            with self.assertRaises(SecurityEventStoreError):
                self.store.append({"event_type": "test"})


if __name__ == "__main__":
    unittest.main()
