from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

DATABASE_URL = os.getenv("JAS_SI_TEST_DATABASE_URL")
try:
    import psycopg
except ImportError:
    psycopg = None

from jas_si_agent.api_key_registry import ApiKeyError, PostgresApiKeyRegistry
from jas_si_agent.postgres_security_event_store import (
    PostgresSecurityEventStore,
)


@unittest.skipUnless(
    DATABASE_URL and psycopg is not None,
    "PostgreSQL integration database is not configured",
)
class TestAtomicApiKeyProvisioning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn = DATABASE_URL
        cls.pepper = b"atomic-test-only-pepper-minimum-32-bytes"
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
        # This suite must use a dedicated disposable PostgreSQL test database.
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "TRUNCATE jas_si_audit_events, jas_si_api_keys, "
                    "jas_si_tenants RESTART IDENTITY CASCADE"
                )
                cursor.execute("DELETE FROM jas_si_audit_chain_state")

    def _tenant(self):
        return self.registry.create_tenant("Atomic provisioning test tenant")

    def _issue(self, tenant_id, run_id=None):
        return self.registry.issue_key_with_audit(
            tenant_id=tenant_id,
            key_name="atomic-test-key",
            scopes=["authorization:check"],
            created_by="integration-test-operator",
            provisioning_run_id=run_id or f"test:{uuid4()}",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )

    def _counts(self):
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT count(*) FROM jas_si_api_keys")
                keys = cursor.fetchone()[0]
                cursor.execute(
                    "SELECT count(*) FROM jas_si_api_key_provisioning_runs"
                )
                runs = cursor.fetchone()[0]
                cursor.execute(
                    """
                    SELECT count(*)
                    FROM jas_si_audit_events
                    WHERE event_payload->>'event_type' = 'api_key_issued'
                    """
                )
                events = cursor.fetchone()[0]
        return keys, runs, events

    def test_success_commits_key_run_and_audit_event_together(self):
        tenant_id = self._tenant()
        issued = self._issue(tenant_id, "test:success")

        self.assertEqual(self._counts(), (1, 1, 1))
        self.assertTrue(
            PostgresSecurityEventStore(self.dsn).verify_integrity()["valid"]
        )
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT event_payload
                    FROM jas_si_audit_events
                    WHERE event_payload->>'key_id' = %s
                    """,
                    (str(issued.key_id),),
                )
                payload = cursor.fetchone()[0]
        self.assertEqual(payload["provisioning_run_id"], "test:success")
        self.assertNotIn("token", payload)
        self.assertNotIn("secret", payload)
        self.assertNotIn("digest", payload)
        self.assertNotIn(issued.token, str(payload))

    def test_failure_after_audit_writes_rolls_back_everything(self):
        tenant_id = self._tenant()
        original = PostgresSecurityEventStore.append_in_transaction

        def append_then_fail(connection, event):
            original(connection, event)
            raise RuntimeError("injected failure after audit insert/checkpoint")

        with patch.object(
            PostgresSecurityEventStore,
            "append_in_transaction",
            side_effect=append_then_fail,
        ):
            with self.assertRaises(ApiKeyError):
                self._issue(tenant_id, "test:rollback")

        self.assertEqual(self._counts(), (0, 0, 0))
        result = PostgresSecurityEventStore(self.dsn).verify_integrity()
        self.assertTrue(result["valid"])
        self.assertEqual(result["verified_event_count"], 0)

    def test_duplicate_run_id_cannot_create_second_key(self):
        tenant_id = self._tenant()
        self._issue(tenant_id, "test:duplicate")
        with self.assertRaises(ApiKeyError):
            self._issue(tenant_id, "test:duplicate")
        self.assertEqual(self._counts(), (1, 1, 1))
        self.assertTrue(
            PostgresSecurityEventStore(self.dsn).verify_integrity()["valid"]
        )

    def test_inactive_tenant_creates_no_key_or_audit(self):
        tenant_id = self._tenant()
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE jas_si_tenants SET status='suspended' "
                    "WHERE tenant_id=%s",
                    (tenant_id,),
                )
        with self.assertRaises(ApiKeyError):
            self._issue(tenant_id, "test:suspended")
        self.assertEqual(self._counts(), (0, 0, 0))


if __name__ == "__main__":
    unittest.main()
