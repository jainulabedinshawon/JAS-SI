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
                cur.execute("SELECT 1 FROM pg_roles WHERE rolname='jas_si_runtime'")
                if cur.fetchone() is None:
                    cur.execute("CREATE ROLE jas_si_runtime NOLOGIN")
                for name in (
                    "002_create_tenant_api_keys.sql",
                    "20261110_usage_metering.sql",
                    "20261110_usage_idempotency_fingerprint.sql",
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
                cur.execute("TRUNCATE jas_si_usage_events")
                cur.execute("DELETE FROM jas_si_api_keys")
                cur.execute("DELETE FROM jas_si_tenants")
                for tenant_id, tenant_name in (
                    (self.tenant_a, "Usage Test A"),
                    (self.tenant_b, "Usage Test B"),
                ):
                    cur.execute(
                        "INSERT INTO jas_si_tenants (tenant_id, tenant_name) VALUES (%s, %s)",
                        (tenant_id, tenant_name),
                    )
                for key_id, tenant_id, prefix in (
                    (self.key_a, self.tenant_a, "jassi_test_a"),
                    (self.key_b, self.tenant_b, "jassi_test_b"),
                    (self.key_c, self.tenant_a, "jassi_test_c"),
                ):
                    cur.execute(
                        """INSERT INTO jas_si_api_keys
                           (key_id, tenant_id, key_name, key_prefix,
                            secret_digest, scopes, created_by)
                           VALUES (%s,%s,'integration',%s,%s,
                                   ARRAY['authorization:check'],'ci')""",
                        (key_id, tenant_id, prefix, b"x" * 32),
                    )

    def test_runtime_role_can_append_and_read_but_not_mutate_usage(self):
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT
                         has_table_privilege('jas_si_runtime', 'jas_si_usage_events', 'SELECT'),
                         has_table_privilege('jas_si_runtime', 'jas_si_usage_events', 'INSERT'),
                         has_table_privilege('jas_si_runtime', 'jas_si_usage_events', 'UPDATE'),
                         has_table_privilege('jas_si_runtime', 'jas_si_usage_events', 'DELETE'),
                         has_table_privilege('jas_si_runtime', 'jas_si_usage_events', 'TRUNCATE')"""
                )
                privileges = cur.fetchone()
        self.assertEqual(privileges, (True, True, False, False, False))

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
