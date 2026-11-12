"""PostgreSQL integration tests for standalone customer identity."""
from __future__ import annotations

import os
import sys
import unittest
import uuid
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

from jas_si_agent.customer_rate_limit import PostgresCustomerRateLimiter
from jas_si_agent.customer_identity import (
    CustomerIdentityConflict,
    CustomerIdentityError,
    PostgresCustomerIdentityStore,
)


@unittest.skipUnless(
    DATABASE_URL and psycopg is not None,
    "PostgreSQL integration database is not configured",
)
class TestPostgresCustomerIdentity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin_dsn = DATABASE_URL
        with psycopg.connect(cls.admin_dsn) as conn, conn.cursor() as cur:
            for role in (
                "jas_si_customer_runtime",
                "jas_si_runtime",
                "jas_si_provisioner",
            ):
                cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,))
                if cur.fetchone() is None:
                    cur.execute(f'CREATE ROLE "{role}" NOLOGIN')
            # Build the same tenant/RLS foundation used by the customer
            # application before exercising its dedicated runtime role.
            for name in (
                "001_create_audit_tables.sql",
                "002_create_tenant_api_keys.sql",
                "003_atomic_api_key_provisioning.sql",
                "004_audit_event_id_identity.sql",
                "005_provisioner_tenant_row_lock.sql",
                "006_api_key_registry_role_grants.sql",
                "007_customer_api_key_self_service.sql",
                "20261110_customer_identity.sql",
                "20261112_customer_identity_routines.sql",
                "20261110_customer_rate_limits.sql",
                "20261110_usage_metering.sql",
                "20261110_usage_idempotency_fingerprint.sql",
                "20261111_usage_append_only_role_grants.sql",
            ):
                migration_path = ROOT / "src" / "jas_si_agent" / "migrations" / name
                cur.execute(migration_path.read_text(encoding="utf-8"))
            # The admin DSN is fixture-only; app traffic uses a dedicated NOINHERIT login.
            cls.login_role = "jas_si_identity_login_" + uuid.uuid4().hex
            cls.login_password = uuid.uuid4().hex + uuid.uuid4().hex
            cur.execute(
                f"CREATE ROLE \"{cls.login_role}\" LOGIN NOINHERIT "
                f"PASSWORD '{cls.login_password}' NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            )
            cur.execute(f'GRANT jas_si_customer_runtime TO "{cls.login_role}" WITH INHERIT FALSE, SET TRUE, ADMIN FALSE')
        cls.login_dsn = make_conninfo(
            cls.admin_dsn, user=cls.login_role, password=cls.login_password
        )
        cls.dsn = make_conninfo(
            cls.login_dsn, options="-c role=jas_si_customer_runtime"
        )
        cls.pepper = b"customer-identity-test-pepper-32-bytes-minimum"
        cls.store = PostgresCustomerIdentityStore(cls.dsn, cls.pepper)
        if not cls.store.verify_schema():
            raise AssertionError("Customer identity DSN did not validate its dedicated LOGIN principal")
        if PostgresCustomerIdentityStore(cls.admin_dsn, cls.pepper).verify_schema():
            raise AssertionError("Administrative test DSN unexpectedly passed the customer role guard")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "login_role", None):
            with psycopg.connect(cls.admin_dsn) as conn, conn.cursor() as cur:
                cur.execute(f'REVOKE jas_si_customer_runtime FROM "{cls.login_role}"')
                cur.execute(f'DROP ROLE "{cls.login_role}"')
        super().tearDownClass()

    def test_runtime_login_is_separate_non_inheriting_and_cannot_assume_operator_role(self):
        with psycopg.connect(self.dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT session_user, current_user")
            self.assertEqual(cur.fetchone(), (self.login_role, "jas_si_customer_runtime"))
            cur.execute("RESET ROLE")
            cur.execute("SELECT session_user, current_user")
            self.assertEqual(cur.fetchone(), (self.login_role, "jas_si_customer_runtime"))
        self.assertFalse(PostgresCustomerIdentityStore(self.login_dsn, self.pepper).verify_schema())
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with psycopg.connect(self.dsn) as conn, conn.cursor() as cur:
                cur.execute("RESET ROLE")
                cur.execute("SET ROLE jas_si_provisioner")

    def setUp(self):
        self.email = f"customer-{uuid.uuid4().hex}@example.test"
        self.organization = "JAS-SI Integration Test"

    def _has_runtime_table_privilege(self, table, privilege, column=None):
        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            if column is None:
                cur.execute(
                    """SELECT has_table_privilege(%s, %s, %s)
                              OR has_any_column_privilege(%s, %s, %s)""",
                    (
                        "jas_si_customer_runtime", table, privilege,
                        "jas_si_customer_runtime", table, privilege,
                    ),
                )
            else:
                cur.execute(
                    "SELECT has_column_privilege(%s, %s, %s, %s)",
                    ("jas_si_customer_runtime", table, column, privilege),
                )
            return bool(cur.fetchone()[0])


    def test_registration_email_verification_login_and_revocation(self):
        verification = self.store.register(self.email, self.organization)
        self.assertEqual(verification.purpose, "verify_email")
        self.assertNotIn(verification.token, repr(verification.account_id))
        account = self.store.verify_email(verification.token)
        self.assertEqual(account.email, self.email)
        self.assertEqual(account.status, "active")

        login = self.store.issue_login_link(self.email)
        self.assertIsNotNone(login)
        session = self.store.consume_login_link(login.token)
        self.assertEqual(session.account.account_id, account.account_id)
        self.assertEqual(
            self.store.authenticate_session(session.token).account_id,
            account.account_id,
        )
        self.assertTrue(self.store.revoke_session(session.token))
        self.assertIsNone(self.store.authenticate_session(session.token))

    def test_verification_and_login_links_are_single_use(self):
        verification = self.store.register(self.email, self.organization)
        self.store.verify_email(verification.token)
        with self.assertRaises(CustomerIdentityError):
            self.store.verify_email(verification.token)
        login = self.store.issue_login_link(self.email)
        self.store.consume_login_link(login.token)
        with self.assertRaises(CustomerIdentityError):
            self.store.consume_login_link(login.token)

    def test_duplicate_registration_is_a_conflict(self):
        self.store.register(self.email, self.organization)
        with self.assertRaises(CustomerIdentityConflict):
            self.store.register(self.email, self.organization)

    def test_login_link_does_not_exist_for_unknown_or_pending_account(self):
        self.assertIsNone(self.store.issue_login_link(self.email))
        self.store.register(self.email, self.organization)
        self.assertIsNone(self.store.issue_login_link(self.email))

    def test_pending_account_can_resend_verification_link(self):
        self.store.register(self.email, self.organization)
        link = self.store.issue_verification_link(self.email)
        self.assertIsNotNone(link)
        self.assertEqual(link.purpose, "verify_email")
        self.store.verify_email(link.token)

    def test_shared_rate_limit_is_atomic_and_shared_across_instances(self):
        pepper = b"customer-rate-limit-test-pepper-32-bytes-minimum"
        first = PostgresCustomerRateLimiter(self.dsn, pepper)
        second = PostgresCustomerRateLimiter(self.dsn, pepper)
        ip = "203.0.113.77"
        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM jas_si_customer_rate_limits WHERE bucket_key = %s",
                (first._bucket_key(ip),),
            )
        self.assertTrue(first.verify_schema())
        self.assertFalse(
            PostgresCustomerRateLimiter(self.admin_dsn, pepper).verify_schema(),
            "Administrative DSN must not pass the customer rate-limiter role guard",
        )
        self.assertEqual(first.check(ip, limit=2, window_seconds=60)[0], True)
        self.assertEqual(second.check(ip, limit=2, window_seconds=60)[0], True)
        allowed, retry_after = first.check(ip, limit=2, window_seconds=60)
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry_after, 1)
        self.assertFalse(second.check(ip, limit=2, window_seconds=60)[0])

    def test_rate_limit_persists_only_keyed_ip_digest(self):
        limiter = PostgresCustomerRateLimiter(
            self.dsn, b"customer-rate-limit-test-pepper-32-bytes-minimum"
        )
        ip = "198.51.100.23"
        key = limiter._bucket_key(ip)
        self.assertEqual(len(key), 32)
        self.assertNotIn(ip.encode("ascii"), key)
        self.assertTrue(limiter.check(ip, limit=5, window_seconds=60)[0])
        with psycopg.connect(self.dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT bucket_key FROM jas_si_customer_rate_limits WHERE bucket_key=%s",
                (key,),
            )
            row = cur.fetchone()
        self.assertIsNotNone(row)

    def test_identity_routines_are_database_owned_and_ready(self):
        self.assertTrue(self.store.verify_security_boundary())
        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT count(*), bool_and(prosecdef),
                          bool_and(proconfig @> ARRAY['search_path=pg_catalog']),
                          bool_and(pg_get_userbyid(proowner) = 'jas_si_customer_identity_owner')
                   FROM pg_proc
                   WHERE pronamespace = 'public'::regnamespace
                     AND proname IN ('customer_register','customer_issue_link',
                         'customer_consume_link','customer_authenticate_session',
                         'customer_revoke_session')"""
            )
            self.assertEqual(cur.fetchone(), (5, True, True, True))
            cur.execute(
                """SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
                          rolreplication, rolbypassrls, rolinherit,
                          EXISTS (SELECT 1 FROM pg_auth_members m WHERE
                                  m.member = r.oid OR m.roleid = r.oid)
                   FROM pg_roles r WHERE rolname='jas_si_customer_identity_owner'"""
            )
            self.assertEqual(cur.fetchone(), (False, False, False, False, False, False, False, False))

    def test_runtime_cannot_read_identity_tables_or_tenants_directly(self):
        with psycopg.connect(self.dsn) as conn, conn.cursor() as cur:
            for table in ('public.jas_si_tenants','public.jas_si_customer_accounts',
                          'public.jas_si_customer_auth_tokens','public.jas_si_customer_sessions'):
                with self.subTest(table=table):
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        cur.execute(f'SELECT * FROM {table} LIMIT 1')
                    conn.rollback()

    def test_identity_privilege_guard_rejects_table_and_column_grants(self):
        role = 'jas_si_customer_runtime'
        probes = (
            ('public.jas_si_customer_accounts', 'SELECT', None),
            ('public.jas_si_customer_accounts', 'INSERT', None),
            ('public.jas_si_customer_accounts', 'UPDATE', None),
            ('public.jas_si_customer_accounts', 'DELETE', None),
            ('public.jas_si_customer_accounts', 'TRUNCATE', None),
            ('public.jas_si_customer_accounts', 'REFERENCES', None),
            ('public.jas_si_customer_accounts', 'TRIGGER', None),
            ('public.jas_si_customer_auth_tokens', 'SELECT', None),
            ('public.jas_si_customer_auth_tokens', 'INSERT', None),
            ('public.jas_si_customer_auth_tokens', 'UPDATE', None),
            ('public.jas_si_customer_sessions', 'SELECT', None),
            ('public.jas_si_customer_sessions', 'INSERT', None),
            ('public.jas_si_customer_sessions', 'UPDATE', None),
            ('public.jas_si_customer_accounts', 'SELECT', 'organization_name'),
            ('public.jas_si_customer_accounts', 'INSERT', 'email'),
            ('public.jas_si_customer_accounts', 'UPDATE', 'status'),
            ('public.jas_si_customer_auth_tokens', 'SELECT', 'token_digest'),
            ('public.jas_si_customer_auth_tokens', 'UPDATE', 'consumed_at'),
            ('public.jas_si_customer_sessions', 'SELECT', 'token_digest'),
            ('public.jas_si_customer_sessions', 'UPDATE', 'revoked_at'),
            ('public.jas_si_customer_tenants', 'INSERT', 'tenant_id'),
        )
        for table, privilege, column in probes:
            if table == 'public.jas_si_customer_tenants':
                table = 'public.jas_si_tenants'
            with self.subTest(table=table, privilege=privilege, column=column):
                with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
                    if column:
                        cur.execute(f'GRANT {privilege} ({column}) ON TABLE {table} TO {role}')
                    else:
                        cur.execute(f'GRANT {privilege} ON TABLE {table} TO {role}')
                try:
                    self.assertFalse(self.store.verify_security_boundary())
                finally:
                    with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
                        if column:
                            cur.execute(f'REVOKE {privilege} ({column}) ON TABLE {table} FROM {role}')
                        else:
                            cur.execute(f'REVOKE {privilege} ON TABLE {table} FROM {role}')

    def test_runtime_role_is_limited_to_customer_identity_tables(self):
        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT
                     has_table_privilege('jas_si_customer_runtime', 'jas_si_tenants', 'SELECT'),
                     has_column_privilege('jas_si_customer_runtime', 'jas_si_tenants', 'tenant_id', 'INSERT'),
                     has_table_privilege('jas_si_customer_runtime', 'jas_si_customer_accounts', 'SELECT'),
                     has_table_privilege('jas_si_customer_runtime', 'jas_si_customer_accounts', 'INSERT'),
                     has_table_privilege('jas_si_customer_runtime', 'jas_si_customer_auth_tokens', 'SELECT'),
                     has_table_privilege('jas_si_customer_runtime', 'jas_si_customer_sessions', 'SELECT'),
                     has_table_privilege('jas_si_customer_runtime', 'jas_si_api_keys', 'INSERT'),
                     has_table_privilege('jas_si_customer_runtime', 'jas_si_audit_events', 'INSERT'),
                     has_table_privilege('jas_si_customer_runtime', 'jas_si_usage_events', 'INSERT'),
                     has_table_privilege('jas_si_customer_runtime', 'jas_si_customer_rate_limits', 'SELECT'),
                     has_table_privilege('jas_si_customer_runtime', 'jas_si_customer_rate_limits', 'INSERT'),
                     has_table_privilege('jas_si_customer_runtime', 'jas_si_customer_rate_limits', 'UPDATE'),
                     has_table_privilege('jas_si_customer_runtime', 'jas_si_customer_rate_limits', 'DELETE')"""
            )
            privileges = cur.fetchone()
        self.assertEqual(privileges, (False, False, False, False, False, False, False, False, False, True, True, True, False))

if __name__ == "__main__":
    unittest.main()
