from __future__ import annotations

import hashlib
import hmac
import os
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
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

from jas_si_agent.api_key_registry import ApiKeyError, PostgresApiKeyRegistry, parse_token
from jas_si_agent.customer_identity import PostgresCustomerIdentityStore
from jas_si_agent.postgres_security_event_store import PostgresSecurityEventStore


@unittest.skipUnless(DATABASE_URL and psycopg is not None, "PostgreSQL integration database is not configured")
class TestCustomerApiKeySecurityBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin_dsn = DATABASE_URL
        with psycopg.connect(cls.admin_dsn) as conn, conn.cursor() as cur:
            for role in ("jas_si_customer_runtime", "jas_si_customer_key_runtime", "jas_si_runtime", "jas_si_provisioner"):
                cur.execute("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s", (role,))
                if cur.fetchone() is None:
                    cur.execute(f'CREATE ROLE "{role}" NOLOGIN')
            migrations = [
                "001_create_audit_tables.sql",
                "002_create_tenant_api_keys.sql",
                "003_atomic_api_key_provisioning.sql",
                "004_audit_event_id_identity.sql",
                "005_provisioner_tenant_row_lock.sql",
                "006_api_key_registry_role_grants.sql",
                "007_customer_api_key_self_service.sql",
                "20261110_customer_identity.sql",
                "20261112_customer_identity_routines.sql",
                "20261113_customer_api_key_routines.sql",
                "20261115_api_key_auth_boundary.sql",
            ]
            for name in migrations:
                path = ROOT / "src" / "jas_si_agent" / "migrations" / name
                cur.execute(path.read_text(encoding="utf-8"))
            cls.identity_login = "jas_si_identity_test_" + uuid.uuid4().hex
            cls.key_login = "jas_si_key_test_" + uuid.uuid4().hex
            cls.identity_password = uuid.uuid4().hex + uuid.uuid4().hex
            cls.key_password = uuid.uuid4().hex + uuid.uuid4().hex
            cur.execute(f'CREATE ROLE "{cls.identity_login}" LOGIN NOINHERIT PASSWORD \'{cls.identity_password}\' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
            cur.execute(f'CREATE ROLE "{cls.key_login}" LOGIN NOINHERIT PASSWORD \'{cls.key_password}\' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
            cur.execute(f'GRANT jas_si_customer_runtime TO "{cls.identity_login}" WITH INHERIT FALSE, SET TRUE, ADMIN FALSE')
            cur.execute(f'GRANT jas_si_customer_key_runtime TO "{cls.key_login}" WITH INHERIT FALSE, SET TRUE, ADMIN FALSE')

        cls.identity_dsn = make_conninfo(cls.admin_dsn, user=cls.identity_login, password=cls.identity_password, options="-c role=jas_si_customer_runtime")
        cls.key_dsn = make_conninfo(cls.admin_dsn, user=cls.key_login, password=cls.key_password, options="-c role=jas_si_customer_key_runtime")
        cls.identity_pepper = b"customer-identity-test-pepper-32-bytes-minimum"
        cls.api_pepper = b"customer-api-key-test-pepper-32-bytes-minimum"
        cls.identity = PostgresCustomerIdentityStore(cls.identity_dsn, cls.identity_pepper)
        cls.registry = PostgresApiKeyRegistry(cls.key_dsn, cls.api_pepper, customer_session_pepper=cls.identity_pepper)
        cls.auth_registry = PostgresApiKeyRegistry(cls.admin_dsn, cls.api_pepper)
        if not cls.identity.verify_security_boundary():
            raise AssertionError("Customer identity database boundary is not ready")
        if not cls.registry.verify_customer_runtime_role():
            raise AssertionError("Customer API-key runtime role is not ready")
        if not cls.registry.verify_customer_audit_isolation():
            raise AssertionError("Customer API-key direct-table privileges remain")
        if not cls.registry.verify_customer_key_table_isolation():
            raise AssertionError("Customer API-key table privileges are not isolated")
        if not cls.registry.verify_customer_key_routines():
            raise AssertionError("Customer API-key routines are not ready")

    @classmethod
    def tearDownClass(cls):
        with psycopg.connect(cls.admin_dsn) as conn, conn.cursor() as cur:
            for role, login in (
                ("jas_si_customer_runtime", getattr(cls, "identity_login", None)),
                ("jas_si_customer_key_runtime", getattr(cls, "key_login", None)),
            ):
                if login:
                    cur.execute(f'REVOKE "{role}" FROM "{login}"')
                    cur.execute(f'DROP ROLE "{login}"')
        super().tearDownClass()

    def setUp(self):
        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute("TRUNCATE public.jas_si_audit_events, public.jas_si_api_keys, public.jas_si_tenants RESTART IDENTITY CASCADE")
            cur.execute("DELETE FROM public.jas_si_audit_chain_state")

    def _session(self, email: str):
        verification = self.identity.register(email, "JAS-SI Security Test")
        self.identity.verify_email(verification.token)
        link = self.identity.issue_login_link(email)
        self.assertIsNotNone(link)
        session_token = self.identity.consume_login_link(link.token).token
        return session_token

    def test_database_derives_tenant_from_session_and_audits_atomically(self):
        session_a = self._session("alpha-" + uuid.uuid4().hex + "@example.test")
        session_b = self._session("beta-" + uuid.uuid4().hex + "@example.test")
        digest_a = self.identity._digest(session_a)
        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute("SET ROLE jas_si_customer_key_owner")
            cur.execute(
                """SELECT a.account_id,a.tenant_id,a.status,t.status,s.expires_at,s.revoked_at
                   FROM public.jas_si_customer_sessions s
                   JOIN public.jas_si_customer_accounts a ON a.account_id=s.account_id
                   JOIN public.jas_si_tenants t ON t.tenant_id=a.tenant_id
                   WHERE s.token_digest=%s AND s.revoked_at IS NULL
                     AND s.expires_at>pg_catalog.clock_timestamp()
                     AND a.status='active' AND t.status='active'
                   FOR SHARE OF s,a,t""",
                (digest_a,),
            )
            self.assertIsNotNone(cur.fetchone(), "SECURITY DEFINER owner must see and lock a valid customer session")
            cur.execute("RESET ROLE")

        issued_a = self.registry.customer_issue_key(
            session_a, "alpha production", ["authorization:check", "usage:read"],
            datetime.now(timezone.utc) + timedelta(days=30),
        )
        issued_b = self.registry.customer_issue_key(
            session_b, "beta staging", ["outcomes:submit"],
            datetime.now(timezone.utc) + timedelta(days=30),
        )

        keys_a = self.registry.customer_list_keys(session_a)
        keys_b = self.registry.customer_list_keys(session_b)
        self.assertEqual([row["key_id"] for row in keys_a], [str(issued_a.key_id)])
        self.assertEqual([row["key_id"] for row in keys_b], [str(issued_b.key_id)])
        self.assertFalse(self.registry.customer_revoke_key(session_a, issued_b.key_id))
        self.assertTrue(self.registry.customer_revoke_key(session_a, issued_a.key_id))
        self.assertFalse(self.registry.customer_revoke_key(session_a, issued_a.key_id))

        audit = PostgresSecurityEventStore(self.admin_dsn).verify_integrity()
        self.assertTrue(audit["valid"])
        self.assertEqual(audit["verified_event_count"], 3)

    def test_forged_and_expired_sessions_fail_closed(self):
        forged = "x" * 43
        with self.assertRaises(ApiKeyError):
            self.registry.customer_list_keys(forged)
        with self.assertRaises(ApiKeyError):
            self.registry.customer_issue_key(forged, "forged", ["usage:read"])
        with self.assertRaises(ApiKeyError):
            self.registry.customer_revoke_key(forged, uuid.uuid4())

        session = self._session("expired-" + uuid.uuid4().hex + "@example.test")
        digest = self.identity._digest(session)
        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute("UPDATE public.jas_si_customer_sessions SET created_at=NOW()-INTERVAL '2 minutes', expires_at=NOW()-INTERVAL '1 minute' WHERE token_digest=%s", (digest,))
        with self.assertRaises(ApiKeyError):
            self.registry.customer_list_keys(session)

    def test_guc_tenant_spoofing_cannot_grant_direct_table_access_or_change_scope(self):
        session_a = self._session("guc-a-" + uuid.uuid4().hex + "@example.test")
        session_b = self._session("guc-b-" + uuid.uuid4().hex + "@example.test")
        key_a = self.registry.customer_issue_key(session_a, "alpha", ["usage:read"])
        self.registry.customer_issue_key(session_b, "beta", ["usage:read"])
        with psycopg.connect(self.key_dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_catalog.set_config('jas_si.tenant_id', '00000000-0000-0000-0000-000000000000', true)")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cur.execute("SELECT * FROM public.jas_si_api_keys")
            conn.rollback()
        keys = self.registry.customer_list_keys(session_a)
        self.assertEqual([row["key_id"] for row in keys], [str(key_a.key_id)])

    def test_customer_key_routine_readiness_rejects_unsafe_owner_role(self):
        # A SECURITY DEFINER owner must remain a non-login, non-privileged,
        # non-member role after migration; drift must fail closed.
        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute("ALTER ROLE jas_si_customer_key_owner LOGIN")
        try:
            self.assertFalse(self.registry.verify_customer_key_routines())
        finally:
            with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
                cur.execute("ALTER ROLE jas_si_customer_key_owner NOLOGIN")
        self.assertTrue(self.registry.verify_customer_key_routines())

    def test_customer_runtime_has_execute_only_not_direct_table_privileges(self):
        protected = (
            "jas_si_tenants", "jas_si_api_keys", "jas_si_api_key_provisioning_runs",
            "jas_si_audit_events", "jas_si_audit_chain_state",
            "jas_si_customer_accounts", "jas_si_customer_auth_tokens", "jas_si_customer_sessions",
        )
        with psycopg.connect(self.key_dsn) as conn, conn.cursor() as cur:
            for table in protected:
                with self.subTest(table=table):
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        cur.execute(f"SELECT * FROM public.{table} LIMIT 1")
                    conn.rollback()
            cur.execute("SELECT has_function_privilege(current_user,'public.customer_api_key_list(bytea)','EXECUTE'), has_function_privilege(current_user,'public.jas_si_customer_key_append_audit(jsonb)','EXECUTE')")
            self.assertEqual(cur.fetchone(), (True, False))


    def test_bearer_api_key_authentication_is_database_owned_and_runtime_isolated(self):
        tenant_id = self.auth_registry.create_tenant("bearer-auth-" + uuid.uuid4().hex)
        issued = self.auth_registry.issue_key(
            tenant_id, "bearer-auth", ["authorization:check", "usage:read"],
            "integration-test",
        )
        authenticated = self.auth_registry.authenticate(issued.token)
        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated.tenant_id, tenant_id)
        self.assertEqual(authenticated.key_id, issued.key_id)
        self.assertEqual(
            authenticated.scopes,
            frozenset({"authorization:check", "usage:read"}),
        )
        _, secret = parse_token(issued.token)
        expected_digest = hmac.new(self.api_pepper, secret, hashlib.sha256).digest()
        self.assertEqual(authenticated.candidate_digest, expected_digest)
        self.assertNotIn(expected_digest.hex(), repr(authenticated))

        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT has_function_privilege('jas_si_runtime', "
                        "'public.jas_si_api_key_authenticate(uuid,bytea)', 'EXECUTE'), "
                        "has_function_privilege('jas_si_runtime', "
                        "'public.jas_si_api_key_authenticate(uuid,bytea)', 'EXECUTE') "
                        "AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode("
                        "COALESCE((SELECT proacl FROM pg_catalog.pg_proc "
                        "WHERE oid='public.jas_si_api_key_authenticate(uuid,bytea)'::regprocedure), "
                        "pg_catalog.acldefault('f', (SELECT proowner FROM pg_catalog.pg_proc "
                        "WHERE oid='public.jas_si_api_key_authenticate(uuid,bytea)'::regprocedure)))) a "
                        "WHERE a.grantee=0 AND a.privilege_type='EXECUTE')")
            self.assertEqual(cur.fetchone(), (True, True))
            cur.execute("SET ROLE jas_si_runtime")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cur.execute("SELECT secret_digest FROM public.jas_si_api_keys LIMIT 1")
            conn.rollback()

        self.assertIsNone(self.auth_registry.authenticate(
            issued.token[:-1] + ("A" if issued.token[-1] != "A" else "B")
        ))

    def test_api_key_auth_boundary_readiness_verifies_routine_and_runtime_isolation(self):
        self.assertTrue(self.auth_registry.verify_api_key_auth_boundary())

    def test_api_key_auth_boundary_readiness_rejects_unsafe_owner_role(self):
        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute("ALTER ROLE jas_si_api_key_auth_owner LOGIN")
        try:
            self.assertFalse(self.auth_registry.verify_api_key_auth_boundary())
        finally:
            with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
                cur.execute("ALTER ROLE jas_si_api_key_auth_owner NOLOGIN")
        self.assertTrue(self.auth_registry.verify_api_key_auth_boundary())

    def test_api_key_auth_owner_is_non_login_unprivileged_and_isolated(self):
        with psycopg.connect(self.admin_dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,"
                "rolreplication,rolbypassrls,rolinherit FROM pg_catalog.pg_roles "
                "WHERE rolname='jas_si_api_key_auth_owner'"
            )
            self.assertEqual(cur.fetchone(), (False, False, False, False, False, False, False))
            cur.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m "
                "JOIN pg_catalog.pg_roles r ON r.oid=m.member "
                "JOIN pg_catalog.pg_roles membership_grantor ON membership_grantor.oid=m.grantor "
                "WHERE r.rolname='jas_si_api_key_auth_owner' OR "
                "(EXISTS (SELECT 1 FROM pg_catalog.pg_roles rr "
                "WHERE rr.oid=m.roleid AND rr.rolname='jas_si_api_key_auth_owner') "
                "AND NOT ((r.rolname='neondb_owner' AND NOT m.admin_option "
                "AND NOT m.inherit_option AND m.set_option) OR (r.rolname='neondb_owner' AND membership_grantor.rolname='cloud_admin' "
                "AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)))))"
            )
            self.assertFalse(cur.fetchone()[0])

    def test_sql_audit_hashing_accepts_existing_python_hash_chain(self):
        store = PostgresSecurityEventStore(self.admin_dsn)
        store.append({
            "event_type": "legacy_python_hash_probe",
            "message": "Unicode compatibility: বাংলা",
            "amount": 1.25,
            "nested": {"enabled": True, "items": [1, 2, 3]},
        })
        session = self._session("hash-" + uuid.uuid4().hex + "@example.test")
        self.registry.customer_issue_key(session, "hash-compat", ["usage:read"])
        self.assertTrue(store.verify_integrity()["valid"])


if __name__ == "__main__":
    unittest.main()
