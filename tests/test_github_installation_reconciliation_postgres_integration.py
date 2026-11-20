"""PostgreSQL integration tests for authoritative GitHub App reconciliation."""
from __future__ import annotations

import hashlib
import json
import os
import unittest
import uuid

import psycopg

DSN = os.environ.get("JAS_SI_MIGRATION_REPLAY_DATABASE_URL")


@unittest.skipUnless(DSN, "PostgreSQL migration replay DSN is not configured")
class GitHubInstallationReconciliationPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='jas_si_github_reconciler_test'"
            )
            if cur.fetchone() is None:
                raise AssertionError("Migration replay must provision reconciler test LOGIN")

    def _fixture(self):
        tenant_id, account_id, session_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        session_token = uuid.uuid4().bytes + uuid.uuid4().bytes
        session_digest = hashlib.sha256(session_token).digest()
        installation_id = 983450000 + (uuid.uuid4().int % 1000000)
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute("SET ROLE jas_si_customer_identity_owner")
            cur.execute(
                "INSERT INTO public.jas_si_tenants(tenant_id,tenant_name) VALUES (%s,%s)",
                (tenant_id, "reconcile-" + tenant_id.hex),
            )
            cur.execute(
                """INSERT INTO public.jas_si_customer_accounts(
                     account_id,tenant_id,email,email_normalized,organization_name
                   ) VALUES (%s,%s,%s,%s,%s)""",
                (account_id, tenant_id, account_id.hex+"@example.test",
                 account_id.hex+"@example.test", "Reconciliation Integration"),
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
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION jas_si_customer_runtime_test")
            cur.execute("SET ROLE jas_si_customer_runtime")
            cur.execute(
                """SELECT claim_id,status,installation_id
                     FROM public.customer_github_installation_claim_record(
                       %s,%s,%s::bigint,%s::bigint,%s,%s::bigint,%s,%s,%s::bigint
                     )""",
                (session_digest, uuid.uuid4(), installation_id, 123456,
                 "jas-user", 7654321, "jas-org", "Organization", 4567),
            )
            claim = cur.fetchone()
        return tenant_id, installation_id, claim

    def _reconcile(
        self, installation_id, *, app_id=4567, account_id=7654321,
        account_login="jas-org", account_type="Organization",
        suspended=False, missing=False, repositories=None,
    ):
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION jas_si_github_reconciler_test")
            cur.execute("SET ROLE jas_si_github_reconciler")
            cur.execute(
                """SELECT claim_status,installation_status,repository_count
                     FROM public.jas_si_github_installation_reconcile_apply(
                       %s,%s,%s,%s,%s,%s,%s,%s::jsonb
                     )""",
                (
                    installation_id, app_id, account_id, account_login,
                    account_type, suspended, missing,
                    json.dumps(repositories if repositories is not None else []),
                ),
            )
            return cur.fetchone()

    @staticmethod
    def _repo(repo_id, full_name, private=True):
        return {"id": repo_id, "full_name": full_name, "private": private}

    def test_pending_claim_becomes_active_only_from_matching_snapshot(self):
        tenant_id, installation_id, claim = self._fixture()
        result = self._reconcile(
            installation_id,
            repositories=[
                self._repo(1001, "jas-org/alpha"),
                self._repo(1002, "jas-org/beta", False),
            ],
        )
        self.assertEqual(result, ("active", "active", 2))
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT status,reconciled_at FROM public.jas_si_github_installation_claims WHERE claim_id=%s",
                (claim[0],),
            )
            self.assertEqual(cur.fetchone()[0], "active")
            cur.execute(
                "SELECT status,verified_at FROM public.jas_si_github_app_installations WHERE installation_id=%s AND tenant_id=%s",
                (installation_id, tenant_id),
            )
            self.assertEqual(cur.fetchone()[0], "active")
            cur.execute(
                """SELECT repository_full_name,status,github_repository_id,is_private
                     FROM public.jas_si_github_app_installation_repositories
                    WHERE installation_id=%s ORDER BY repository_full_name""",
                (installation_id,),
            )
            self.assertEqual(cur.fetchall(), [
                ("jas-org/alpha", "active", 1001, True),
                ("jas-org/beta", "active", 1002, False),
            ])

    def test_duplicate_repository_id_in_snapshot_is_rejected(self):
        _, installation_id, _ = self._fixture()
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self._reconcile(
                installation_id,
                repositories=[
                    self._repo(1001, "jas-org/alpha"),
                    self._repo(1001, "jas-org/renamed-alpha"),
                ],
            )
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM public.jas_si_github_app_installations WHERE installation_id=%s",
                (installation_id,),
            )
            self.assertEqual(cur.fetchone()[0], 0)

    def test_full_snapshot_revokes_removed_repository(self):
        _, installation_id, _ = self._fixture()
        self._reconcile(
            installation_id,
            repositories=[
                self._repo(1001, "jas-org/alpha"),
                self._repo(1002, "jas-org/beta"),
            ],
        )
        result = self._reconcile(
            installation_id,
            repositories=[self._repo(1001, "jas-org/alpha")],
        )
        self.assertEqual(result, ("active", "active", 1))
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT repository_full_name,status
                     FROM public.jas_si_github_app_installation_repositories
                    WHERE installation_id=%s ORDER BY repository_full_name""",
                (installation_id,),
            )
            self.assertEqual(cur.fetchall(), [
                ("jas-org/alpha", "active"),
                ("jas-org/beta", "revoked"),
            ])

    def test_account_or_app_mismatch_fails_closed(self):
        _, installation_id, _ = self._fixture()
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self._reconcile(
                installation_id, account_id=999999,
                repositories=[self._repo(1001, "jas-org/alpha")],
            )
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self._reconcile(
                installation_id, app_id=999999,
                repositories=[self._repo(1001, "jas-org/alpha")],
            )
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM public.jas_si_github_app_installations WHERE installation_id=%s",
                (installation_id,),
            )
            self.assertEqual(cur.fetchone()[0], 0)

    def test_suspension_and_unsuspension_follow_live_snapshot(self):
        _, installation_id, claim = self._fixture()
        self._reconcile(
            installation_id,
            repositories=[self._repo(1001, "jas-org/alpha")],
        )
        self.assertEqual(
            self._reconcile(installation_id, suspended=True),
            ("suspended", "revoked", 0),
        )
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM public.jas_si_github_installation_claims WHERE claim_id=%s",
                (claim[0],),
            )
            self.assertEqual(cur.fetchone()[0], "suspended")
            cur.execute(
                "SELECT status FROM public.jas_si_github_app_installations WHERE installation_id=%s",
                (installation_id,),
            )
            self.assertEqual(cur.fetchone()[0], "revoked")
        self.assertEqual(
            self._reconcile(
                installation_id,
                repositories=[self._repo(1001, "jas-org/alpha")],
            ),
            ("active", "active", 1),
        )

    def test_deleted_installation_revokes_binding_and_claim(self):
        _, installation_id, claim = self._fixture()
        self._reconcile(
            installation_id,
            repositories=[self._repo(1001, "jas-org/alpha")],
        )
        self.assertEqual(
            self._reconcile(installation_id, missing=True),
            ("revoked", "revoked", 0),
        )
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM public.jas_si_github_installation_claims WHERE claim_id=%s",
                (claim[0],),
            )
            self.assertEqual(cur.fetchone()[0], "revoked")
            cur.execute(
                "SELECT status FROM public.jas_si_github_app_installations WHERE installation_id=%s",
                (installation_id,),
            )
            self.assertEqual(cur.fetchone()[0], "revoked")

    def test_missing_claim_is_not_activated(self):
        result = self._reconcile(
            987654321, repositories=[self._repo(1001, "jas-org/alpha")]
        )
        self.assertEqual(result, ("NO_CLAIM", "UNCHANGED", 0))

    def test_pending_claim_polling_has_bounded_retry_and_stops_after_reconcile(self):
        _, installation_id, _ = self._fixture()
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION jas_si_github_reconciler_test")
            cur.execute("SET ROLE jas_si_github_reconciler")
            cur.execute(
                "SELECT installation_id,attempt_count FROM public.jas_si_github_installation_claim_pending(50)"
            )
            first_batch = cur.fetchall()
            self.assertIn((installation_id, 1), first_batch)
            cur.execute(
                "SELECT installation_id,attempt_count FROM public.jas_si_github_installation_claim_pending(50)"
            )
            second_batch = cur.fetchall()
            self.assertNotIn(installation_id, [row[0] for row in second_batch])
        self._reconcile(
            installation_id,
            repositories=[self._repo(1001, "jas-org/alpha")],
        )
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION jas_si_github_reconciler_test")
            cur.execute("SET ROLE jas_si_github_reconciler")
            cur.execute(
                "SELECT installation_id,attempt_count FROM public.jas_si_github_installation_claim_pending(50)"
            )
            remaining = cur.fetchall()
            self.assertNotIn(installation_id, [row[0] for row in remaining])

    def test_retry_exhaustion_moves_claim_to_needs_review(self):
        _, installation_id, claim = self._fixture()
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute(
                """UPDATE public.jas_si_github_installation_claims
                      SET reconcile_attempt_count=9,
                          reconcile_next_attempt_at=clock_timestamp()
                    WHERE claim_id=%s""",
                (claim[0],),
            )
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION jas_si_github_reconciler_test")
            cur.execute("SET ROLE jas_si_github_reconciler")
            cur.execute(
                "SELECT installation_id,attempt_count FROM public.jas_si_github_installation_claim_pending(50)"
            )
            self.assertIn((installation_id, 10), cur.fetchall())
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute(
                """UPDATE public.jas_si_github_installation_claims
                      SET reconcile_next_attempt_at=clock_timestamp()
                    WHERE claim_id=%s""",
                (claim[0],),
            )
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION jas_si_github_reconciler_test")
            cur.execute("SET ROLE jas_si_github_reconciler")
            cur.execute(
                "SELECT installation_id,attempt_count FROM public.jas_si_github_installation_claim_pending(50)"
            )
            self.assertNotIn(installation_id, [row[0] for row in cur.fetchall()])
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT status,reconcile_attempt_count,reconcile_exhausted_at
                     FROM public.jas_si_github_installation_claims WHERE claim_id=%s""",
                (claim[0],),
            )
            status, attempts, exhausted_at = cur.fetchone()
            self.assertEqual(status, "needs_review")
            self.assertEqual(attempts, 10)
            self.assertIsNotNone(exhausted_at)
        self.assertEqual(
            self._reconcile(
                installation_id,
                repositories=[self._repo(1001, "jas-org/alpha")],
            ),
            ("needs_review", "UNCHANGED", 0),
        )

    def test_dedicated_reconciler_login_sets_only_its_capability(self):
        _, installation_id, _ = self._fixture()
        test_password = "integration-only-reconciler-login-password"
        with psycopg.connect(DSN, autocommit=True) as admin, admin.cursor() as cur:
            cur.execute(
                "ALTER ROLE jas_si_github_reconciler_login LOGIN PASSWORD 'integration-only-reconciler-login-password'"
            )
        login_dsn = psycopg.conninfo.make_conninfo(
            DSN,
            user="jas_si_github_reconciler_login",
            password=test_password,
        )
        try:
            with psycopg.connect(login_dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT session_user")
                self.assertEqual(cur.fetchone()[0], "jas_si_github_reconciler_login")
                cur.execute("SET ROLE jas_si_github_reconciler")
                cur.execute("SELECT current_user")
                self.assertEqual(cur.fetchone()[0], "jas_si_github_reconciler")
                cur.execute(
                    "SELECT installation_id,attempt_count FROM public.jas_si_github_installation_claim_pending(50)"
                )
                claimed = cur.fetchall()
                self.assertIn((installation_id, 1), claimed)
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    cur.execute(
                        "SELECT installation_id FROM public.jas_si_github_installation_claims"
                    )
        finally:
            with psycopg.connect(DSN, autocommit=True) as admin, admin.cursor() as cur:
                cur.execute("ALTER ROLE jas_si_github_reconciler_login NOLOGIN")

    def test_reconciler_has_execute_only_access(self):
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION jas_si_github_reconciler_test")
            cur.execute("SET ROLE jas_si_github_reconciler")
            for statement in (
                "SELECT installation_id FROM public.jas_si_github_installation_claims",
                "SELECT installation_id FROM public.jas_si_github_app_installations",
                "SELECT delivery_id FROM public.jas_si_github_webhook_inbox",
            ):
                with self.subTest(statement=statement):
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        cur.execute(statement)
                    conn.rollback()
                    cur.execute("SET SESSION AUTHORIZATION jas_si_github_reconciler_test")
                    cur.execute("SET ROLE jas_si_github_reconciler")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cur.execute(
                    """SELECT * FROM public.jas_si_github_webhook_receive(
                         'denied','installation','created',98765,%s,'{}'::jsonb
                       )""",
                    (b"\x00" * 32,),
                )


    def test_database_rejects_consecutive_hyphens_in_verified_github_logins(self):
        tenant_id, installation_id, claim = self._fixture()
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg.errors.CheckViolation):
                cur.execute(
                    "UPDATE public.jas_si_github_installation_claims SET github_user_login='jas--user' WHERE claim_id=%s",
                    (claim[0],),
                )
        self._reconcile(
            installation_id,
            repositories=[self._repo(1001, "jas-org/alpha")],
        )
        with psycopg.connect(DSN) as conn, conn.cursor() as cur:
            with self.assertRaises(psycopg.errors.CheckViolation):
                cur.execute(
                    "UPDATE public.jas_si_github_app_installations SET account_login='jas--org' WHERE installation_id=%s",
                    (installation_id,),
                )
            with self.assertRaises(psycopg.errors.CheckViolation):
                cur.execute(
                    "UPDATE public.jas_si_github_app_installation_repositories SET repository_full_name='jas--org/alpha' WHERE installation_id=%s",
                    (installation_id,),
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
