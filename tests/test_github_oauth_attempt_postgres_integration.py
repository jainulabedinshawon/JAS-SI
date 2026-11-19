"""PostgreSQL integration tests for durable, tenant-bound GitHub OAuth attempts."""
from __future__ import annotations

import hashlib
import os
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import psycopg

DSN = os.environ.get("JAS_SI_MIGRATION_REPLAY_DATABASE_URL")


@unittest.skipUnless(DSN, "PostgreSQL migration replay DSN is not configured")
class GitHubOAuthAttemptPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin_dsn = DSN
        with psycopg.connect(cls.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_customer_runtime_test'"
            )
            if cur.fetchone() is None:
                raise AssertionError("Migration replay must provision the customer runtime test LOGIN")

    def _fixture(self):
        tenant_id, account_id, session_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        session_secret = uuid.uuid4().bytes + uuid.uuid4().bytes
        session_digest = hashlib.sha256(session_secret).digest()
        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute("SET ROLE jas_si_customer_identity_owner")
            cur.execute(
                "INSERT INTO public.jas_si_tenants(tenant_id,tenant_name) VALUES (%s,%s)",
                (tenant_id, "oauth-it-" + tenant_id.hex),
            )
            cur.execute(
                """INSERT INTO public.jas_si_customer_accounts(
                     account_id,tenant_id,email,email_normalized,organization_name
                   ) VALUES (%s,%s,%s,%s,%s)""",
                (account_id, tenant_id, account_id.hex+"@example.test",
                 account_id.hex+"@example.test", "OAuth Integration"),
            )
            cur.execute(
                "UPDATE public.jas_si_customer_accounts SET status='active',email_verified_at=clock_timestamp() WHERE account_id=%s",
                (account_id,),
            )
            cur.execute(
                """INSERT INTO public.jas_si_customer_sessions(
                     session_id,account_id,token_digest,expires_at
                   ) VALUES (%s,%s,%s,clock_timestamp()+interval '1 hour')""",
                (session_id, account_id, session_digest),
            )
        return tenant_id, account_id, session_digest

    def _runtime_connection(self):
        conn = psycopg.connect(self.admin_dsn)
        with conn.cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION jas_si_customer_runtime_test")
            cur.execute("SET ROLE jas_si_customer_runtime")
        return conn

    def _create_attempt(self, session_digest, state_digest):
        with self._runtime_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT attempt_id,expires_at
                     FROM public.customer_github_oauth_attempt_create(
                       %s,%s,%s,%s,%s,%s,%s,%s
                     )""",
                (session_digest, uuid.uuid4(), 9876500, state_digest, b"\x01"*71,
                 "test-key-v1", hashlib.sha256(b"https://jas-si.example.test/oauth/callback").digest(),
                 datetime.now(timezone.utc)+timedelta(minutes=5)),
            )
            return cur.fetchone()

    def _record_claim(self, session_digest, installation_id, *, user_id=12345):
        with self._runtime_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT claim_id,status,installation_id
                     FROM public.customer_github_installation_claim_record(
                       %s,%s,%s,%s,%s,%s,%s,%s,%s
                     )""",
                (
                    session_digest, uuid.uuid4(), installation_id, user_id,
                    "jas-user", 7654321, "jas-org", "Organization", 4567,
                ),
            )
            return cur.fetchone()

    def test_verified_installation_claim_is_durable_and_pending(self):
        _, _, session_digest = self._fixture()
        result = self._record_claim(session_digest, 9876501)
        self.assertIsNotNone(result)
        self.assertEqual(result[1], "pending_reconciliation")
        self.assertEqual(result[2], 9876501)
        with self._runtime_connection() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cur.execute(
                    "SELECT installation_id FROM public.jas_si_github_installation_claims"
                )
            conn.rollback()

    def test_installation_claim_is_idempotent_for_same_identity(self):
        _, _, session_digest = self._fixture()
        first = self._record_claim(session_digest, 9876502)
        second = self._record_claim(session_digest, 9876502)
        self.assertEqual(first, second)

    def test_installation_claim_rejects_different_customer_or_github_identity(self):
        _, _, session_digest = self._fixture()
        _, _, other_session_digest = self._fixture()
        first = self._record_claim(session_digest, 9876503)
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self._record_claim(other_session_digest, 9876503)
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self._record_claim(session_digest, 9876503, user_id=54321)
        self.assertEqual(first[1], "pending_reconciliation")

    def test_oauth_attempt_is_session_bound_and_direct_table_access_is_denied(self):
        _, _, session_digest = self._fixture()
        state_digest = hashlib.sha256(uuid.uuid4().bytes).digest()
        attempt = self._create_attempt(session_digest, state_digest)
        self.assertIsNotNone(attempt)
        with self._runtime_connection() as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cur.execute("SELECT state_digest FROM public.jas_si_github_oauth_attempts")
            conn.rollback()

    def test_concurrent_callback_consumption_is_exactly_once(self):
        _, _, session_digest = self._fixture()
        state_digest = hashlib.sha256(uuid.uuid4().bytes).digest()
        self._create_attempt(session_digest, state_digest)
        redirect_digest = hashlib.sha256(b"https://jas-si.example.test/oauth/callback").digest()
        barrier = threading.Barrier(2)

        def consume():
            with self._runtime_connection() as conn, conn.cursor() as cur:
                barrier.wait(timeout=5)
                cur.execute(
                    """SELECT attempt_id,tenant_id,account_id,candidate_installation_id,
                              verifier_ciphertext,verifier_key_version
                         FROM public.customer_github_oauth_attempt_consume(%s,%s,%s)""",
                    (session_digest, state_digest, redirect_digest),
                )
                return cur.fetchone()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: consume(), range(2)))
        self.assertEqual(sum(result is not None for result in results), 1)
        winner = next(result for result in results if result is not None)
        self.assertEqual(winner[3], 9876500)
        self.assertEqual(winner[4], b"\x01"*71)
        self.assertEqual(winner[5], "test-key-v1")

    def test_callback_cannot_be_consumed_by_a_different_customer_session(self):
        _, _, session_digest = self._fixture()
        _, _, other_session_digest = self._fixture()
        state_digest = hashlib.sha256(uuid.uuid4().bytes).digest()
        self._create_attempt(session_digest, state_digest)
        redirect_digest = hashlib.sha256(b"https://jas-si.example.test/oauth/callback").digest()
        with self._runtime_connection() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT attempt_id
                     FROM public.customer_github_oauth_attempt_consume(%s,%s,%s)""",
                (other_session_digest, state_digest, redirect_digest),
            )
            self.assertIsNone(cur.fetchone())
            cur.execute(
                """SELECT attempt_id
                     FROM public.customer_github_oauth_attempt_consume(%s,%s,%s)""",
                (session_digest, state_digest, redirect_digest),
            )
            self.assertIsNotNone(cur.fetchone())


if __name__ == "__main__":
    unittest.main(verbosity=2)
