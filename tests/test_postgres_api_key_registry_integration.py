from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

DATABASE_URL = os.getenv("JAS_SI_TEST_DATABASE_URL")
try:
    import psycopg
except ImportError:
    psycopg = None

from jas_si_agent.api_key_registry import (
    ALLOWED_SCOPES,
    ApiKeyError,
    PostgresApiKeyRegistry,
    parse_token,
)


@unittest.skipUnless(
    DATABASE_URL and psycopg is not None,
    "PostgreSQL integration database is not configured",
)
class TestPostgresApiKeyRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn = DATABASE_URL
        cls.pepper = b"test-only-api-key-pepper-32-bytes-minimum"
        cls.registry = PostgresApiKeyRegistry(cls.dsn, cls.pepper)
        migrations = [
            ROOT / "src/jas_si_agent/migrations/001_create_audit_tables.sql",
            ROOT / "src/jas_si_agent/migrations/002_create_tenant_api_keys.sql",
            ROOT / "src/jas_si_agent/migrations/003_atomic_api_key_provisioning.sql",
        ]
        with psycopg.connect(cls.dsn) as connection:
            with connection.cursor() as cursor:
                for migration in migrations:
                    cursor.execute(migration.read_text(encoding="utf-8"))

    def setUp(self):
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute("TRUNCATE jas_si_api_keys, jas_si_tenants CASCADE")

    def _tenant(self):
        return self.registry.create_tenant("Pilot Customer")

    def test_issue_and_authenticate_returns_tenant_and_scopes(self):
        tenant_id = self._tenant()
        issued = self.registry.issue_key(
            tenant_id, "pilot staging",
            ["authorization:check", "github:evidence:verify"],
            "operator@example.invalid",
            datetime.now(timezone.utc) + timedelta(days=7),
        )
        self.assertTrue(issued.token.startswith("jassi_live_"))
        key_id, secret = parse_token(issued.token)
        self.assertEqual(key_id, issued.key_id)
        self.assertEqual(len(secret), 32)
        authenticated = self.registry.authenticate(issued.token)
        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated.tenant_id, tenant_id)
        self.assertEqual(
            authenticated.scopes,
            frozenset({"authorization:check", "github:evidence:verify"}),
        )

    def test_raw_token_is_not_stored_in_database(self):
        tenant_id = self._tenant()
        issued = self.registry.issue_key(
            tenant_id, "one-time", ["outcomes:submit"], "operator"
        )
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT secret_digest::text FROM jas_si_api_keys WHERE key_id = %s",
                    (issued.key_id,),
                )
                stored = cursor.fetchone()[0]
        self.assertNotIn(issued.token, stored)
        self.assertNotIn(issued.token.encode(), stored.encode())

    def test_revoked_key_is_rejected(self):
        tenant_id = self._tenant()
        issued = self.registry.issue_key(
            tenant_id, "revoke", ["outcomes:submit"], "operator"
        )
        self.assertTrue(self.registry.revoke_key(issued.key_id))
        self.assertIsNone(self.registry.authenticate(issued.token))
        self.assertFalse(self.registry.revoke_key(issued.key_id))

    def test_expired_key_is_rejected(self):
        tenant_id = self._tenant()
        issued = self.registry.issue_key(
            tenant_id, "expired", ["outcomes:submit"], "operator",
            datetime.now(timezone.utc) + timedelta(seconds=2),
        )
        import time
        time.sleep(2.1)
        self.assertIsNone(self.registry.authenticate(issued.token))

    def test_suspended_tenant_key_is_rejected(self):
        tenant_id = self._tenant()
        issued = self.registry.issue_key(
            tenant_id, "suspended", ["outcomes:submit"], "operator"
        )
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE jas_si_tenants SET status = 'suspended' WHERE tenant_id = %s",
                    (tenant_id,),
                )
        self.assertIsNone(self.registry.authenticate(issued.token))

    def test_unknown_scope_is_rejected_before_insert(self):
        tenant_id = self._tenant()
        with self.assertRaises(ApiKeyError):
            self.registry.issue_key(
                tenant_id, "bad scope", ["admin:*"], "operator"
            )

    def test_unknown_token_is_rejected(self):
        self.assertIsNone(self.registry.authenticate("jassi_live_invalid"))


if __name__ == "__main__":
    unittest.main()
