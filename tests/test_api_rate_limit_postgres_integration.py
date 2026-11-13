"""PostgreSQL integration tests for the shared strict API rate limiter."""
from __future__ import annotations

import os
import sys
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

DATABASE_URL = os.getenv("JAS_SI_TEST_DATABASE_URL")
try:
    import psycopg
    from psycopg.conninfo import make_conninfo
except ImportError:
    psycopg = None
    make_conninfo = None

from jas_si_agent.api_rate_limit import PostgresApiRateLimiter


@unittest.skipUnless(
    DATABASE_URL and psycopg is not None,
    "PostgreSQL integration database is not configured",
)
class TestPostgresApiRateLimiter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin_dsn = DATABASE_URL
        cls.login_role = "jas_si_api_limit_login_" + uuid.uuid4().hex
        cls.login_password = uuid.uuid4().hex + uuid.uuid4().hex
        migration = (
            ROOT / "src" / "jas_si_agent" / "migrations"
            / "20261118_shared_api_rate_limits.sql"
        )
        with psycopg.connect(cls.admin_dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_runtime'")
                if cur.fetchone() is None:
                    cur.execute("CREATE ROLE jas_si_runtime NOLOGIN NOINHERIT")
                migration_sql = migration.read_text(encoding="utf-8")
                cur.execute(migration_sql)
                # Replaying the migration against an already-provisioned schema
                # must be safe and preserve the owner/runtime privilege boundary.
                cur.execute(migration_sql)
                cur.execute(
                    f'CREATE ROLE "{cls.login_role}" LOGIN NOINHERIT '
                    f"PASSWORD '{cls.login_password}' NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
                )
                cur.execute(
                    f'GRANT jas_si_runtime TO "{cls.login_role}" '
                    "WITH INHERIT FALSE, SET TRUE, ADMIN FALSE"
                )
        cls.runtime_dsn = make_conninfo(
            cls.admin_dsn,
            user=cls.login_role,
            password=cls.login_password,
            options="-c role=jas_si_runtime",
        )
        cls.pepper = b"jas-si-api-rate-limit-test-pepper-32-bytes"
        cls.first = PostgresApiRateLimiter(cls.runtime_dsn, cls.pepper)
        cls.second = PostgresApiRateLimiter(cls.runtime_dsn, cls.pepper)
        if not cls.first.verify_schema():
            raise AssertionError("Dedicated API runtime role failed limiter schema verification")
        if PostgresApiRateLimiter(cls.admin_dsn, cls.pepper).verify_schema():
            raise AssertionError("Administrative database role passed API runtime readiness")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "login_role", None):
            with psycopg.connect(cls.admin_dsn, autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute(f'REVOKE jas_si_runtime FROM "{cls.login_role}"')
                    cur.execute(f'DROP ROLE "{cls.login_role}"')
        super().tearDownClass()

    def _clear_bucket(self, limiter, ip):
        with psycopg.connect(self.admin_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM public.jas_si_api_rate_limits WHERE bucket_key=%s",
                    (limiter._bucket_key(ip),),
                )

    def test_atomic_limit_is_shared_across_two_runtime_instances(self):
        ip = "198.51.100.241"
        self._clear_bucket(self.first, ip)

        def request(index):
            limiter = self.first if index % 2 == 0 else self.second
            return limiter.check(ip, limit=3, window_seconds=60)

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(request, range(12)))
        self.assertEqual(sum(1 for allowed, _, _ in results if allowed), 3)
        self.assertEqual(sum(1 for allowed, _, _ in results if not allowed), 9)
        self.assertTrue(all(remaining == 0 for allowed, remaining, _ in results if not allowed))
        self.assertTrue(all(1 <= retry <= 60 for allowed, _, retry in results if not allowed))

    def test_sliding_window_expiry_and_retry_after(self):
        ip = "198.51.100.242"
        self._clear_bucket(self.first, ip)
        self.assertEqual(
            self.first.check(ip, limit=1, window_seconds=1),
            (True, 0, 0),
        )
        allowed, remaining, retry_after = self.second.check(
            ip, limit=1, window_seconds=1
        )
        self.assertFalse(allowed)
        self.assertEqual(remaining, 0)
        self.assertGreaterEqual(retry_after, 1)
        self.assertLessEqual(retry_after, 1)
        time.sleep(1.1)
        self.assertEqual(
            self.second.check(ip, limit=1, window_seconds=1),
            (True, 0, 0),
        )

    def test_runtime_role_cannot_read_or_write_limiter_table_directly(self):
        with psycopg.connect(self.runtime_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT pg_catalog.has_table_privilege(
                               current_user,'public.jas_si_api_rate_limits','SELECT')
                              OR pg_catalog.has_any_column_privilege(
                               current_user,'public.jas_si_api_rate_limits','SELECT')
                              OR pg_catalog.has_table_privilege(
                               current_user,'public.jas_si_api_rate_limits','INSERT')
                              OR pg_catalog.has_table_privilege(
                               current_user,'public.jas_si_api_rate_limits','UPDATE')
                              OR pg_catalog.has_table_privilege(
                               current_user,'public.jas_si_api_rate_limits','DELETE')
                              OR pg_catalog.has_table_privilege(
                               current_user,'public.jas_si_api_rate_limits','TRUNCATE')
                              OR pg_catalog.has_any_column_privilege(
                               current_user,'public.jas_si_api_rate_limits','INSERT')
                              OR pg_catalog.has_any_column_privilege(
                               current_user,'public.jas_si_api_rate_limits','UPDATE')"""
                )
                self.assertFalse(cur.fetchone()[0])
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with psycopg.connect(self.runtime_dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT * FROM public.jas_si_api_rate_limits LIMIT 1")

    def test_indexed_cleanup_removes_old_buckets_in_bounded_batch(self):
        stale_key = uuid.uuid4().bytes + uuid.uuid4().bytes
        with psycopg.connect(self.admin_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO public.jas_si_api_rate_limits
                           (bucket_key,request_times,updated_at)
                       VALUES (%s,ARRAY[]::timestamptz[],NOW()-INTERVAL '15 days')""",
                    (stale_key,),
                )
        self.first.check("198.51.100.243", limit=5, window_seconds=60)
        with psycopg.connect(self.admin_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM public.jas_si_api_rate_limits WHERE bucket_key=%s",
                    (stale_key,),
                )
                self.assertIsNone(cur.fetchone())


if __name__ == "__main__":
    unittest.main()
