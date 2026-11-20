from __future__ import annotations

import sys
import types
import unittest
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

_EXECUTED_SQL = []

from jas_si_agent.agent_task_worker_store import (
    AgentTaskLease,
    PostgresAgentTaskWorkerStore,
)


class FakeCursor:
    def __init__(self, row):
        self.row = row
        self.executed = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, query, params):
        _EXECUTED_SQL.append(query)
        self.executed = (query, params)

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, row, capture):
        self.cursor_instance = FakeCursor(row)
        self.capture = capture

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.capture.append(self.cursor_instance.executed)
        return False

    def cursor(self):
        return self.cursor_instance


class AgentTaskWorkerStoreTests(unittest.TestCase):
    worker_id = uuid.UUID("00000000-0000-0000-0000-000000000001")

    def make_store(self):
        return PostgresAgentTaskWorkerStore("postgresql://worker", self.worker_id)

    def install_fake_psycopg(self, row, capture):
        _EXECUTED_SQL.clear()
        def connect(dsn):
            self.assertEqual(dsn, "postgresql://worker")
            return FakeConnection(row, capture)

        psycopg = types.ModuleType("psycopg")
        psycopg.connect = connect
        psycopg_types = types.ModuleType("psycopg.types")
        psycopg_json = types.ModuleType("psycopg.types.json")

        class Jsonb:
            def __init__(self, obj):
                self.obj = obj

        psycopg_json.Jsonb = Jsonb
        modules = {
            "psycopg": psycopg,
            "psycopg.types": psycopg_types,
            "psycopg.types.json": psycopg_json,
        }
        return patch.dict(sys.modules, modules), Jsonb

    def test_claim_maps_database_lease(self):
        task_id = uuid.uuid4()
        expires = datetime.now(timezone.utc)
        capture = []
        context, _ = self.install_fake_psycopg(
            (task_id, uuid.UUID("00000000-0000-0000-0000-000000000099"), "reasoning", {"prompt": "test"}, 1, 3, 7, expires),
            capture,
        )
        with context:
            lease = self.make_store().claim(lease_seconds=45)

        self.assertEqual(
            lease, AgentTaskLease(task_id, uuid.UUID("00000000-0000-0000-0000-000000000099"), "reasoning", {"prompt": "test"}, 1, 3, 7, expires)
        )
        self.assertEqual(capture[0][1], (self.worker_id, 45))
        self.assertIn("SET ROLE jas_si_agent_worker", _EXECUTED_SQL)
        self.assertEqual(lease.tenant_id, uuid.UUID("00000000-0000-0000-0000-000000000099"))
        self.assertIn("tenant_id", capture[0][0])
        self.assertIn("jas_si_agent_task_claim", capture[0][0])

    def test_lease_rejects_missing_or_invalid_tenant_identity(self):
        with self.assertRaises(ValueError):
            AgentTaskLease(
                uuid.uuid4(), None, "reasoning", {}, 1, 2, 1,
                datetime.now(timezone.utc),
            )

    def test_claim_returns_none_for_empty_queue(self):
        capture = []
        context, _ = self.install_fake_psycopg(None, capture)
        with context:
            self.assertIsNone(self.make_store().claim())

    def test_claim_rejects_invalid_lease_before_database(self):
        for seconds in (14, 301, True, 1.5, "60"):
            with self.subTest(seconds=seconds):
                with self.assertRaises(ValueError):
                    self.make_store().claim(lease_seconds=seconds)

    def test_renew_uses_worker_identity_and_fence(self):
        capture = []
        context, _ = self.install_fake_psycopg((True,), capture)
        task_id = uuid.uuid4()
        with context:
            self.assertTrue(self.make_store().renew(
                task_id=task_id, lease_fence=9, lease_seconds=30
            ))
        self.assertEqual(capture[0][1], (self.worker_id, task_id, 9, 30))
        self.assertIn("jas_si_agent_task_renew", capture[0][0])

    def test_report_is_jsonb_and_preserves_verification_gate(self):
        capture = []
        context, Jsonb = self.install_fake_psycopg((True,), capture)
        task_id = uuid.uuid4()
        with context:
            self.assertTrue(self.make_store().report(
                task_id=task_id, lease_fence=2, result_payload={"reported": "done"}
            ))
        params = capture[0][1]
        self.assertIsInstance(params[3], Jsonb)
        self.assertEqual(params[3].obj, {"reported": "done"})
        self.assertIn("jas_si_agent_task_report", capture[0][0])

    def test_report_rejects_non_json_results_without_database(self):
        def forbidden_connect(_dsn):
            self.fail("database must not be called for invalid payloads")

        psycopg = types.ModuleType("psycopg")
        psycopg.connect = forbidden_connect
        for payload in ({"bad": float("nan")}, {"bad": object()}, {"nested": {"x": float("inf")}}):
            with self.subTest(payload=repr(payload)), patch.dict(sys.modules, {"psycopg": psycopg}):
                with self.assertRaises(ValueError):
                    self.make_store().report(
                        task_id=uuid.uuid4(), lease_fence=1, result_payload=payload
                    )

    def test_acknowledge_cancel_uses_current_fence(self):
        capture = []
        context, _ = self.install_fake_psycopg((True,), capture)
        task_id = uuid.uuid4()
        with context:
            self.assertTrue(self.make_store().acknowledge_cancel(
                task_id=task_id, lease_fence=4
            ))
        self.assertEqual(capture[0][1][1:], (task_id, 4))
        self.assertIn("jas_si_agent_task_ack_cancel", capture[0][0])

    def test_fail_returns_database_state(self):
        capture = []
        context, _ = self.install_fake_psycopg(("queued",), capture)
        task_id = uuid.uuid4()
        with context:
            result = self.make_store().fail(
                task_id=task_id, lease_fence=3, error_code="MODEL_TIMEOUT",
                retry_delay_seconds=15,
            )
        self.assertEqual(result, "queued")
        self.assertEqual(capture[0][1][2:], (3, "MODEL_TIMEOUT", 15))

    def test_fail_rejects_invalid_arguments(self):
        cases = (
            {"error_code": "lowercase"},
            {"error_code": "BAD CODE"},
            {"error_code": "x" * 65},
            {"error_code": "VALID", "retry_delay_seconds": -1},
            {"error_code": "VALID", "retry_delay_seconds": 3601},
            {"error_code": "VALID", "retry_delay_seconds": True},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                values = {"error_code": "VALID", "retry_delay_seconds": 0}
                values.update(overrides)
                with self.assertRaises(ValueError):
                    self.make_store().fail(
                        task_id=uuid.uuid4(), lease_fence=1, **values
                    )

    def test_stale_or_invalid_fencing_token_is_rejected(self):
        with self.assertRaises(ValueError):
            self.make_store().renew(task_id=uuid.uuid4(), lease_fence=0)


if __name__ == "__main__":
    unittest.main()
