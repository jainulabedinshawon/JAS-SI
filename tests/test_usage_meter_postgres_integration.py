"""PostgreSQL integration tests for tenant usage metering."""
from __future__ import annotations

import hashlib
import os
import sys
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

DATABASE_URL = os.getenv("JAS_SI_TEST_DATABASE_URL")
try:
    import psycopg
except ImportError:
    psycopg = None

from jas_si_agent.usage_meter import PostgresUsageMeter, UsageMeterError, UsageQuotaExceeded


@unittest.skipUnless(
    DATABASE_URL and psycopg is not None,
    "PostgreSQL integration database is not configured",
)
class TestPostgresUsageMeter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn = DATABASE_URL
        with psycopg.connect(cls.dsn) as conn:
            with conn.cursor() as cur:
                for role in ("jas_si_runtime", "jas_si_provisioner"):
                    cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,))
                    if cur.fetchone() is None:
                        cur.execute(f"CREATE ROLE {role} NOLOGIN")
                for name in (
                    "002_create_tenant_api_keys.sql",
                    "20261110_usage_metering.sql",
                    "20261110_usage_idempotency_fingerprint.sql",
                    "20261111_usage_append_only_role_grants.sql",
                    "20261115_api_key_auth_boundary.sql",
                    "20261116_api_key_bound_usage_routines.sql",
                ):
                    path = ROOT / "src" / "jas_si_agent" / "migrations" / name
                    cur.execute(path.read_text(encoding="utf-8"))
        cls.meter = PostgresUsageMeter(cls.dsn)

    def _record(self, **kwargs):
        kwargs.setdefault(
            "request_fingerprint",
            hashlib.sha256(b"usage-meter-integration-test").hexdigest(),
        )
        kwargs.setdefault("monthly_limit", 100)
        return self.meter.record(**kwargs)

    def setUp(self):
        self.tenant_a = uuid.uuid4()
        self.tenant_b = uuid.uuid4()
        self.key_a = uuid.uuid4()
        self.key_b = uuid.uuid4()
        self.key_c = uuid.uuid4()
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                # Fixtures use fresh UUIDs; never delete shared tenant/key rows.
                # This keeps parallel suites isolated and preserves FK history.
                for tenant_id, tenant_name in (
                    (self.tenant_a, f"Usage Test A {uuid.uuid4().hex}"),
                    (self.tenant_b, f"Usage Test B {uuid.uuid4().hex}"),
                ):
                    cur.execute(
                        "INSERT INTO jas_si_tenants (tenant_id, tenant_name) VALUES (%s, %s)",
                        (tenant_id, tenant_name),
                    )
                for key_id, tenant_id, prefix in (
                    (self.key_a, self.tenant_a, f"jassi_test_a_{uuid.uuid4().hex}"),
                    (self.key_b, self.tenant_b, f"jassi_test_b_{uuid.uuid4().hex}"),
                    (self.key_c, self.tenant_a, f"jassi_test_c_{uuid.uuid4().hex}"),
                ):
                    cur.execute(
                        """INSERT INTO jas_si_api_keys
                           (key_id, tenant_id, key_name, key_prefix,
                            secret_digest, scopes, created_by)
                           VALUES (%s,%s,'integration',%s,%s,%s,'ci')""",
                        (key_id, tenant_id, prefix, b"x" * 32,
                         ["authorization:check", "usage:read"] if key_id != self.key_c else ["authorization:check"]),
                    )

    def test_api_key_usage_routine_readiness_verifies_owner_and_grants(self):
        self.assertTrue(self.meter.verify_api_key_usage_routines())

    def test_api_key_bound_usage_routines_validate_digest_and_scope(self):
        import psycopg
        with psycopg.connect(self.dsn) as conn, conn.cursor() as cur:
            cur.execute("SET ROLE jas_si_runtime")
            cur.execute(
                """SELECT event_id,operation,units,replayed,used_units,remaining_units
                   FROM public.jas_si_api_key_usage_reserve(
                     %s,%s,'authorization:check','routine-1','routine-idem',
                     'authorization.evaluate',%s,1,10)""",
                (self.key_a, b"x" * 32, hashlib.sha256(b"payload").hexdigest()),
            )
            row = cur.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[1:4], ("authorization.evaluate", 1, False))
            self.assertEqual(row[4:6], (1, 9))
            cur.execute(
                """SELECT event_id,replayed,used_units FROM public.jas_si_api_key_usage_reserve(
                     %s,%s,'authorization:check','routine-2','routine-idem',
                     'authorization.evaluate',%s,1,10)""",
                (self.key_a, b"x" * 32, hashlib.sha256(b"payload").hexdigest()),
            )
            replay = cur.fetchone()
            self.assertEqual(replay[0], row[0])
            self.assertEqual(replay[1:], (True, 1))
            with self.assertRaises(psycopg.Error):
                cur.execute(
                    """SELECT * FROM public.jas_si_api_key_usage_reserve(
                         %s,%s,'authorization:check','wrong-digest','wrong-digest',
                         'authorization.evaluate',%s,1,10)""",
                    (self.key_a, b"z" * 32, hashlib.sha256(b"wrong").hexdigest()),
                )
            conn.rollback()

    def test_api_key_bound_usage_reads_derive_tenant_from_key(self):
        import psycopg
        fingerprint_a = hashlib.sha256(b"tenant-a").hexdigest()
        fingerprint_b = hashlib.sha256(b"tenant-b").hexdigest()
        with psycopg.connect(self.dsn) as conn, conn.cursor() as cur:
            cur.execute("SET ROLE jas_si_runtime")
            cur.execute(
                """SELECT event_id FROM public.jas_si_api_key_usage_reserve(
                     %s,%s,'authorization:check','tenant-a','tenant-a',
                     'authorization.evaluate',%s,1,100)""",
                (self.key_a, b"x" * 32, fingerprint_a),
            )
            cur.execute(
                """SELECT event_id FROM public.jas_si_api_key_usage_reserve(
                     %s,%s,'authorization:check','tenant-b','tenant-b',
                     'authorization.evaluate',%s,1,100)""",
                (self.key_b, b"x" * 32, fingerprint_b),
            )
            cur.execute(
                """SELECT operation,event_count,total_units
                   FROM public.jas_si_api_key_usage_summary(%s,%s,'usage:read',%s)""",
                (self.key_a, b"x" * 32, datetime(2000, 1, 1, tzinfo=timezone.utc)),
            )
            summary = cur.fetchall()
            self.assertEqual(summary, [("authorization.evaluate", 1, 1)])
            cur.execute(
                """SELECT used_units,remaining_units,exhausted
                   FROM public.jas_si_api_key_usage_quota(%s,%s,'usage:read',100)""",
                (self.key_a, b"x" * 32),
            )
            self.assertEqual(cur.fetchone(), (1, 99, False))
            with self.assertRaises(psycopg.Error):
                cur.execute(
                    """SELECT * FROM public.jas_si_api_key_usage_summary(
                         %s,%s,'usage:read',%s)""",
                    (self.key_c, b"x" * 32, datetime(2000, 1, 1, tzinfo=timezone.utc)),
                )
            conn.rollback()

    def test_runtime_role_can_append_and_read_but_not_mutate_usage(self):
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT
                         has_table_privilege('jas_si_runtime', 'jas_si_usage_events', 'SELECT'),
                         has_table_privilege('jas_si_runtime', 'jas_si_usage_events', 'INSERT'),
                         has_table_privilege('jas_si_runtime', 'jas_si_usage_events', 'UPDATE'),
                         has_table_privilege('jas_si_runtime', 'jas_si_usage_events', 'DELETE'),
                         has_table_privilege('jas_si_runtime', 'jas_si_usage_events', 'TRUNCATE'),
                         has_table_privilege('jas_si_provisioner', 'jas_si_usage_events', 'SELECT'),
                         has_table_privilege('jas_si_provisioner', 'jas_si_usage_events', 'INSERT'),
                         has_table_privilege('jas_si_provisioner', 'jas_si_usage_events', 'UPDATE'),
                         has_table_privilege('jas_si_provisioner', 'jas_si_usage_events', 'DELETE'),
                         has_table_privilege('jas_si_provisioner', 'jas_si_usage_events', 'TRUNCATE')"""
                )
                privileges = cur.fetchone()
        self.assertEqual(
            privileges,
            (True, True, False, False, False, False, False, False, False, False),
        )

    def test_idempotent_replay_returns_original_event(self):
        args = dict(
            tenant_id=str(self.tenant_a), api_key_id=str(self.key_a),
            request_id="request-1", idempotency_key="idem-1",
            operation="authorization.evaluate",
        )
        first = self._record(**args)
        replay = self._record(**args)
        self.assertFalse(first["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(first["event_id"], replay["event_id"])

    def test_idempotency_conflict_is_rejected(self):
        base = dict(
            tenant_id=str(self.tenant_a), api_key_id=str(self.key_a),
            request_id="request-1", idempotency_key="idem-conflict",
            operation="authorization.evaluate",
        )
        self._record(**base)
        with self.assertRaises(UsageMeterError):
            self._record(**dict(base, operation="outcome.submit"))

    def test_same_key_rejects_changed_request_fingerprint(self):
        base = dict(
            tenant_id=str(self.tenant_a), api_key_id=str(self.key_a),
            request_id="request-fingerprint", idempotency_key="idem-fingerprint",
            operation="authorization.evaluate",
        )
        self._record(**base, request_fingerprint=hashlib.sha256(b"payload-a").hexdigest())
        with self.assertRaises(UsageMeterError):
            self._record(**base, request_fingerprint=hashlib.sha256(b"payload-b").hexdigest())

    def test_same_key_rejects_replay_from_different_api_key(self):
        base = dict(
            tenant_id=str(self.tenant_a), api_key_id=str(self.key_a),
            request_id="request-key", idempotency_key="idem-key",
            operation="authorization.evaluate",
        )
        self._record(**base)
        with self.assertRaises(UsageMeterError):
            self._record(**dict(base, api_key_id=str(self.key_c)))

    def test_tenant_summary_does_not_leak_other_tenant(self):
        self._record(
            tenant_id=str(self.tenant_a), api_key_id=str(self.key_a),
            request_id="a", idempotency_key="a", operation="authorization.evaluate",
        )
        self._record(
            tenant_id=str(self.tenant_b), api_key_id=str(self.key_b),
            request_id="b", idempotency_key="b", operation="outcome.submit",
        )
        summary = self.meter.summary(
            tenant_id=str(self.tenant_a),
            since=datetime(2000, 1, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(summary["events"], 1)
        self.assertEqual(summary["units"], 1)
        self.assertEqual(summary["by_operation"][0]["operation"], "authorization.evaluate")

    def test_database_rejects_tenant_key_mismatch(self):
        with self.assertRaises(Exception):
            self._record(
                tenant_id=str(self.tenant_a), api_key_id=str(self.key_b),
                request_id="mismatch", idempotency_key="mismatch",
                operation="authorization.evaluate",
            )

    def test_usage_history_is_tenant_scoped_and_keyset_paginated(self):
        event_time = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                for tenant_id, key_id, request_id in (
                    (self.tenant_a, self.key_a, "history-a1"),
                    (self.tenant_a, self.key_a, "history-a2"),
                    (self.tenant_b, self.key_b, "history-b1"),
                ):
                    cur.execute(
                        """INSERT INTO jas_si_usage_events
                           (event_id, tenant_id, api_key_id, request_id, idempotency_key,
                            operation, units, occurred_at, request_fingerprint)
                           VALUES (%s,%s,%s,%s,%s,'authorization.evaluate',1,%s,%s)""",
                        (uuid.uuid4(), tenant_id, key_id, request_id, request_id,
                         event_time, hashlib.sha256(request_id.encode()).hexdigest()),
                    )
        page_one = self.meter.events(tenant_id=str(self.tenant_a), limit=1)
        self.assertEqual(len(page_one["items"]), 1)
        self.assertIsNotNone(page_one["next_cursor"])
        cursor = page_one["next_cursor"]
        page_two = self.meter.events(
            tenant_id=str(self.tenant_a), limit=1,
            before=datetime.fromisoformat(cursor["before"]),
            before_event_id=cursor["before_event_id"],
        )
        self.assertEqual(len(page_two["items"]), 1)
        self.assertIsNone(page_two["next_cursor"])
        seen = {item["request_id"] for item in page_one["items"] + page_two["items"]}
        self.assertEqual(seen, {"history-a1", "history-a2"})
        self.assertNotIn("history-b1", seen)

    def test_usage_history_rejects_invalid_cursor_and_limit(self):
        with self.assertRaises(ValueError):
            self.meter.events(tenant_id=str(self.tenant_a), limit=0)
        with self.assertRaises(ValueError):
            self.meter.events(tenant_id=str(self.tenant_a), before=datetime.now(timezone.utc))
        with self.assertRaises(ValueError):
            self.meter.events(tenant_id=str(self.tenant_a), before=datetime.now(timezone.utc),
                              before_event_id="not-a-uuid")

    def test_usage_rows_are_immutable(self):
        event = self._record(
            tenant_id=str(self.tenant_a), api_key_id=str(self.key_a),
            request_id="immutable", idempotency_key="immutable",
            operation="authorization.evaluate",
        )
        with self.assertRaises(psycopg.Error):
            with psycopg.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE jas_si_usage_events SET units=2 WHERE event_id=%s",
                        (uuid.UUID(event["event_id"]),),
                    )


    def test_quota_rejects_new_event_after_limit(self):
        base = dict(
            tenant_id=str(self.tenant_a), api_key_id=str(self.key_a),
            operation="authorization.evaluate", monthly_limit=1,
        )
        self._record(**base, request_id="quota-1", idempotency_key="quota-1")
        with self.assertRaises(UsageQuotaExceeded) as caught:
            self._record(**base, request_id="quota-2", idempotency_key="quota-2")
        self.assertEqual(caught.exception.monthly_limit, 1)
        self.assertEqual(caught.exception.used_units, 1)

    def test_idempotent_replay_does_not_consume_another_quota_unit(self):
        args = dict(
            tenant_id=str(self.tenant_a), api_key_id=str(self.key_a),
            request_id="quota-replay", idempotency_key="quota-replay",
            operation="authorization.evaluate", monthly_limit=1,
        )
        first = self._record(**args)
        replay = self._record(**args)
        self.assertFalse(first["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["used_units"], 1)

    def test_concurrent_requests_cannot_overspend_quota(self):
        from concurrent.futures import ThreadPoolExecutor
        args = [
            dict(tenant_id=str(self.tenant_a), api_key_id=str(self.key_a),
                 request_id=f"concurrent-{i}", idempotency_key=f"concurrent-{i}",
                 operation="authorization.evaluate", monthly_limit=1)
            for i in range(2)
        ]
        def attempt(item):
            try:
                return self._record(**item)["event_id"]
            except UsageQuotaExceeded:
                return "quota_denied"
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, args))
        self.assertEqual(sum(value != "quota_denied" for value in outcomes), 1)
        self.assertEqual(outcomes.count("quota_denied"), 1)


    def test_quota_status_reports_monthly_limit_and_remaining(self):
        self._record(
            tenant_id=str(self.tenant_a), api_key_id=str(self.key_a),
            request_id="quota-status", idempotency_key="quota-status",
            operation="authorization.evaluate", monthly_limit=100,
        )
        status = self.meter.quota_status(
            tenant_id=str(self.tenant_a), monthly_limit=100,
        )
        self.assertEqual(status["monthly_limit"], 100)
        self.assertEqual(status["used_units"], 1)
        self.assertEqual(status["remaining_units"], 99)
        self.assertFalse(status["exhausted"])


if __name__ == "__main__":
    unittest.main()
