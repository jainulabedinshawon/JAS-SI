"""PostgreSQL RLS tests for tenant-scoped customer API-key operations."""
from __future__ import annotations

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

from jas_si_agent.api_key_registry import PostgresApiKeyRegistry


@unittest.skipUnless(DATABASE_URL and psycopg is not None, "PostgreSQL integration database is not configured")
class TestCustomerApiKeyRls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        roles = (
            "jas_si_provisioner",
            "jas_si_runtime",
            "jas_si_customer_runtime",
            "jas_si_customer_key_runtime",
        )
        migrations = (
            "001_create_audit_tables.sql",
            "002_create_tenant_api_keys.sql",
            "003_atomic_api_key_provisioning.sql",
            "004_audit_event_id_identity.sql",
            "005_provisioner_tenant_row_lock.sql",
            "006_api_key_registry_role_grants.sql",
            "20261110_customer_identity.sql",
            "20261110_usage_metering.sql",
            "20261110_usage_idempotency_fingerprint.sql",
            "007_customer_api_key_self_service.sql",
            "20261110_customer_identity.sql",
            "20261112_customer_identity_routines.sql",
            "20261113_customer_api_key_routines.sql",
            "20261115_api_key_auth_boundary.sql",
            "20261121_security_audit_writer_boundary.sql",
        )
        with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
            for role in roles:
                cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,))
                if cur.fetchone() is None:
                    cur.execute(f'CREATE ROLE "{role}" NOLOGIN')
            for name in migrations:
                path = ROOT / "src" / "jas_si_agent" / "migrations" / name
                if path.exists():
                    cur.execute(path.read_text(encoding="utf-8"))
        cls.pepper = b"customer-api-key-test-pepper-32-bytes-minimum"
        cls.login_role = "jas_si_key_login_" + uuid.uuid4().hex
        cls.login_password = uuid.uuid4().hex + uuid.uuid4().hex
        with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
            cur.execute(
                f"CREATE ROLE \"{cls.login_role}\" LOGIN NOINHERIT "
                f"PASSWORD '{cls.login_password}' NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            )
            cur.execute(f'GRANT jas_si_customer_key_runtime TO "{cls.login_role}" WITH INHERIT FALSE, SET TRUE, ADMIN FALSE')
        cls.login_dsn = make_conninfo(
            DATABASE_URL, user=cls.login_role, password=cls.login_password
        )
        cls.customer_dsn = make_conninfo(
            cls.login_dsn, options="-c role=jas_si_customer_key_runtime"
        )
        cls.registry = PostgresApiKeyRegistry(cls.customer_dsn, cls.pepper)

        if not cls.registry.verify_customer_runtime_role():
            raise AssertionError("Customer API-key DSN did not assume the dedicated RLS role")
        if PostgresApiKeyRegistry(DATABASE_URL, cls.pepper).verify_customer_runtime_role():
            raise AssertionError("Administrative test DSN unexpectedly passed the customer role guard")
        if not cls.registry.verify_customer_audit_isolation():
            raise AssertionError("Customer API-key runtime must not have direct audit-table privileges")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "login_role", None):
            with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
                cur.execute(f'REVOKE jas_si_customer_key_runtime FROM "{cls.login_role}"')
                cur.execute(f'DROP ROLE "{cls.login_role}"')
        super().tearDownClass()

    def test_runtime_login_is_separate_non_inheriting_and_cannot_assume_operator_role(self):
        with psycopg.connect(self.customer_dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT session_user, current_user")
            self.assertEqual(cur.fetchone(), (self.login_role, "jas_si_customer_key_runtime"))
            cur.execute("RESET ROLE")
            cur.execute("SELECT session_user, current_user")
            self.assertEqual(cur.fetchone(), (self.login_role, "jas_si_customer_key_runtime"))
        self.assertFalse(PostgresApiKeyRegistry(self.login_dsn, self.pepper).verify_customer_runtime_role())
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with psycopg.connect(self.customer_dsn) as conn, conn.cursor() as cur:
                cur.execute("RESET ROLE")
                cur.execute("SET ROLE jas_si_provisioner")

    def setUp(self):
        self.tenant_a, self.tenant_b = uuid.uuid4(), uuid.uuid4()
        with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO jas_si_tenants (tenant_id,tenant_name) VALUES (%s,%s),(%s,%s)",
                (self.tenant_a, f"RLS-A-{self.tenant_a.hex[:8]}", self.tenant_b, f"RLS-B-{self.tenant_b.hex[:8]}"),
            )
            cur.execute(
                "INSERT INTO jas_si_api_keys (key_id,tenant_id,key_name,key_prefix,secret_digest,pepper_version,scopes,created_by) VALUES (%s,%s,'foreign',%s,%s,1,ARRAY['usage:read'],'test')",
                (uuid.uuid4(), self.tenant_b, f"foreign-{self.tenant_b.hex[:12]}", b"x" * 32),
            )

    def test_operator_role_can_list_tenant_keys(self):
        """Trusted operator listing must not be rejected by the customer-role guard."""
        admin_registry = PostgresApiKeyRegistry(DATABASE_URL, self.pepper)
        issued = admin_registry.issue_key(
            self.tenant_a, "operator-listed", ["authorization:check"], "operator"
        )
        items = admin_registry.list_tenant_keys(self.tenant_a)
        self.assertEqual(
            [item["key_id"] for item in items],
            [str(issued.key_id)],
        )

    def test_customer_key_lifecycle_readiness_uses_database_owned_routines(self):
        """Customer key lifecycle is exposed through session-bound SECURITY DEFINER routines."""
        self.assertTrue(self.registry.verify_customer_audit_isolation())
        self.assertTrue(self.registry.verify_customer_key_table_isolation())
        self.assertTrue(self.registry.verify_customer_key_routines())

    def test_custom_guc_cannot_bypass_customer_table_boundary(self):
        """A caller-controlled tenant GUC cannot grant direct API-key table access."""
        with psycopg.connect(self.customer_dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT set_config('jas_si.tenant_id', %s, true)",
                (str(self.tenant_b),),
            )
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                cur.execute(
                    "SELECT key_id FROM jas_si_api_keys WHERE tenant_id = %s",
                    (self.tenant_b,),
                )

    def test_legacy_direct_lifecycle_path_is_denied_to_customer_runtime(self):
        """Customer runtime cannot use legacy tenant-ID/direct-table operator methods."""
        from jas_si_agent.api_key_registry import ApiKeyError

        with self.assertRaises(ApiKeyError):
            self.registry.issue_key_with_audit(
                tenant_id=self.tenant_a,
                key_name="legacy-direct-path",
                scopes=["authorization:check"],
                created_by="customer",
                provisioning_run_id=f"customer-api:{uuid.uuid4()}",
                tenant_scope=self.tenant_a,
            )

        admin_registry = PostgresApiKeyRegistry(DATABASE_URL, self.pepper)
        foreign = admin_registry.issue_key(
            self.tenant_b, "foreign-owned", ["authorization:check"], "operator"
        )
        with self.assertRaises(ApiKeyError):
            self.registry.revoke_key_with_audit(
                foreign.key_id,
                revoked_by="customer",
                revocation_run_id=f"customer-revoke:{uuid.uuid4()}",
                tenant_scope=self.tenant_a,
            )
        with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM jas_si_api_keys WHERE key_id = %s AND tenant_id = %s",
                (foreign.key_id, self.tenant_b),
            )
            self.assertEqual(cur.fetchone()[0], "active")

    def test_privilege_guard_detects_each_direct_audit_table_grant(self):
        """Exercise every forbidden table privilege, not just the migration's current grants."""
        table = "public.jas_si_audit_events"
        columns = ("event_id", "event_payload", "previous_hash", "event_hash")
        with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
            for protected_table in (
                "public.jas_si_audit_events",
                "public.jas_si_audit_chain_state",
            ):
                cur.execute(
                    f"REVOKE ALL PRIVILEGES ON TABLE {protected_table} "
                    "FROM jas_si_customer_key_runtime"
                )
            cur.execute(
                "REVOKE SELECT (event_id, event_payload, previous_hash, event_hash), "
                "INSERT (event_payload, previous_hash, event_hash), "
                "UPDATE (event_payload, previous_hash, event_hash), "
                "REFERENCES (event_id, event_payload, previous_hash, event_hash) "
                "ON TABLE public.jas_si_audit_events FROM jas_si_customer_key_runtime"
            )
            cur.execute(
                "REVOKE INSERT (singleton, last_hash), SELECT (singleton, last_hash), "
                "UPDATE (last_hash), REFERENCES (singleton, last_hash) "
                "ON TABLE public.jas_si_audit_chain_state FROM jas_si_customer_key_runtime"
            )
        self.assertTrue(
            self.registry.verify_customer_audit_isolation(),
            "The guard should pass after direct audit privileges are removed",
        )

        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
            with self.subTest(privilege=privilege):
                with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
                    cur.execute(
                        f"GRANT {privilege} ON TABLE {table} TO jas_si_customer_key_runtime"
                    )
                try:
                    self.assertFalse(
                        self.registry.verify_customer_audit_isolation(),
                        f"The guard failed to detect direct {privilege} privilege",
                    )
                finally:
                    with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
                        cur.execute(
                            f"REVOKE {privilege} ON TABLE {table} FROM jas_si_customer_key_runtime"
                        )

        with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
            cur.execute(
                "GRANT SELECT (event_payload) ON TABLE public.jas_si_audit_events "
                "TO jas_si_customer_key_runtime"
            )
        try:
            self.assertFalse(
                self.registry.verify_customer_audit_isolation(),
                "The guard failed to detect a column-only audit SELECT grant",
            )
        finally:
            with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
                cur.execute(
                    "REVOKE SELECT (event_payload) ON TABLE public.jas_si_audit_events "
                    "FROM jas_si_customer_key_runtime"
                )
                # Restore the migration's original grants so this test does not
                # change the database contract observed by other integration tests.
                cur.execute(
                    "GRANT INSERT (singleton, last_hash), SELECT (singleton, last_hash), "
                    "UPDATE (last_hash) ON TABLE public.jas_si_audit_chain_state "
                    "TO jas_si_customer_key_runtime"
                )
                cur.execute(
                    "GRANT SELECT (event_id, event_payload, previous_hash, event_hash), "
                    "INSERT (event_payload, previous_hash, event_hash) "
                    "ON TABLE public.jas_si_audit_events TO jas_si_customer_key_runtime"
                )
                cur.execute(
                    "GRANT INSERT (singleton, last_hash), SELECT (singleton, last_hash), "
                    "UPDATE (last_hash) ON TABLE public.jas_si_audit_chain_state "
                    "TO jas_si_customer_key_runtime"
                )


if __name__ == "__main__":
    unittest.main()
