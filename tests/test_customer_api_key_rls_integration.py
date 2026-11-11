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
        cls.customer_dsn = make_conninfo(
            DATABASE_URL, options="-c role=jas_si_customer_key_runtime"
        )
        cls.registry = PostgresApiKeyRegistry(cls.customer_dsn, cls.pepper)

        if not cls.registry.verify_customer_runtime_role():
            raise AssertionError("Customer API-key DSN did not assume the dedicated RLS role")
        if PostgresApiKeyRegistry(DATABASE_URL, cls.pepper).verify_customer_runtime_role():
            raise AssertionError("Administrative test DSN unexpectedly passed the customer role guard")
        if cls.registry.verify_customer_audit_isolation():
            raise AssertionError(
                "Expected the current migration's direct audit grants to be detected until the hardened migration replaces them"
            )

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

    def test_customer_role_lists_only_own_tenant_and_can_issue_and_revoke(self):
        issued = self.registry.issue_key_with_audit(
            tenant_id=self.tenant_a,
            key_name="customer-owned-key",
            scopes=["authorization:check"],
            created_by=f"customer:{uuid.uuid4()}",
            provisioning_run_id=f"customer-api:{uuid.uuid4()}",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            tenant_scope=self.tenant_a,
        )
        listed = self.registry.list_tenant_keys(self.tenant_a)
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["key_id"], str(issued.key_id))
        self.assertNotIn("secret_digest", listed[0])

        # RLS must hide the foreign tenant when the authenticated API has set
        # tenant A as the transaction-local context. Do not call the registry's
        # helper with tenant B here: that helper is trusted to receive the
        # tenant derived from the verified customer session.
        with psycopg.connect(self.customer_dsn) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT set_config('jas_si.tenant_id', %s, true)",
                (str(self.tenant_a),),
            )
            cur.execute("SELECT key_id FROM jas_si_api_keys ORDER BY key_id")
            visible_ids = {str(row[0]) for row in cur.fetchall()}
        self.assertEqual(visible_ids, {str(issued.key_id)})

        self.assertTrue(
            self.registry.revoke_key_with_audit(
                issued.key_id,
                revoked_by=f"customer:{uuid.uuid4()}",
                revocation_run_id=f"customer-revoke:{uuid.uuid4()}",
                tenant_scope=self.tenant_a,
            )
        )
        self.assertEqual(self.registry.list_tenant_keys(self.tenant_a)[0]["status"], "revoked")

    def test_customer_role_cannot_issue_or_revoke_for_another_tenant(self):
        with self.assertRaises(Exception):
            self.registry.issue_key_with_audit(
                tenant_id=self.tenant_b,
                key_name="cross-tenant",
                scopes=["authorization:check"],
                created_by="customer",
                provisioning_run_id=f"customer-api:{uuid.uuid4()}",
                tenant_scope=self.tenant_a,
            )
        admin_registry = PostgresApiKeyRegistry(DATABASE_URL, self.pepper)
        foreign = admin_registry.issue_key(
            self.tenant_b, "foreign-owned", ["authorization:check"], "operator"
        )
        self.assertFalse(
            self.registry.revoke_key_with_audit(
                foreign.key_id,
                revoked_by="customer",
                revocation_run_id=f"customer-revoke:{uuid.uuid4()}",
                tenant_scope=self.tenant_a,
            )
        )
        self.assertEqual(
            admin_registry.list_tenant_keys(self.tenant_b)[0]["status"],
            "active",
        )


if __name__ == "__main__":
    unittest.main()
