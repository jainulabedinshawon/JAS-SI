from __future__ import annotations

import os
import sys
import unittest
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
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
            ROOT / "src/jas_si_agent/migrations/004_audit_event_id_identity.sql",
            ROOT / "src/jas_si_agent/migrations/005_provisioner_tenant_row_lock.sql",
        ]
        with psycopg.connect(cls.dsn) as connection:
            with connection.cursor() as cursor:
                for role in ("jas_si_provisioner", "jas_si_runtime"):
                    cursor.execute(
                        "SELECT 1 FROM pg_roles WHERE rolname = %s",
                        (role,),
                    )
                    if cursor.fetchone() is None:
                        cursor.execute(
                            f"CREATE ROLE {role} NOLOGIN"
                        )
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

    def test_migrations_004_and_005_are_idempotent(self):
        migration_paths = [
            ROOT / "src/jas_si_agent/migrations/004_audit_event_id_identity.sql",
            ROOT / "src/jas_si_agent/migrations/005_provisioner_tenant_row_lock.sql",
        ]
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                for _ in range(2):
                    for migration_path in migration_paths:
                        cursor.execute(migration_path.read_text(encoding="utf-8"))

                cursor.execute(
                    """
                    SELECT is_identity
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='jas_si_audit_events'
                      AND column_name='event_id'
                    """
                )
                self.assertEqual(cursor.fetchone(), ("YES",))

                cursor.execute(
                    """
                    SELECT column_default, is_nullable
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='jas_si_tenants'
                      AND column_name='provisioning_lock_version'
                    """
                )
                self.assertEqual(cursor.fetchone(), ("0", "NO"))

    def test_audit_event_id_has_identity_default(self):
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT is_identity, column_default
                    FROM information_schema.columns
                    WHERE table_schema='public'
                      AND table_name='jas_si_audit_events'
                      AND column_name='event_id'
                    """
                )
                row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "YES")
        self.assertIsNone(row[1])

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

    def _assert_insert_trigger_failure_rolls_back(self, table_name, trigger_name):
        tenant_id = self._tenant()
        function_name = f"{trigger_name}_fn"
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""
                    CREATE OR REPLACE FUNCTION {function_name}()
                    RETURNS trigger
                    LANGUAGE plpgsql
                    AS $$

                    BEGIN
                        RAISE EXCEPTION 'injected {table_name} insert failure';
                    END;
                    $$

                    """
                )
                cursor.execute(
                    f"""
                    CREATE TRIGGER {trigger_name}
                    AFTER INSERT ON {table_name}
                    FOR EACH ROW
                    EXECUTE FUNCTION {function_name}()
                    """
                )
        try:
            with self.assertRaises(ApiKeyError):
                self._issue(tenant_id, f"test:{trigger_name}")
        finally:
            with psycopg.connect(self.dsn) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"DROP TRIGGER IF EXISTS {trigger_name} ON {table_name}"
                    )
                    cursor.execute(f"DROP FUNCTION IF EXISTS {function_name}()")
        self.assertEqual(self._counts(), (0, 0, 0))
        self.assertTrue(
            PostgresSecurityEventStore(self.dsn).verify_integrity()["valid"]
        )

    def test_key_insert_failure_rolls_back_everything(self):
        self._assert_insert_trigger_failure_rolls_back(
            "jas_si_api_keys",
            "jas_si_test_fail_key_insert",
        )

    def test_idempotency_insert_failure_rolls_back_everything(self):
        self._assert_insert_trigger_failure_rolls_back(
            "jas_si_api_key_provisioning_runs",
            "jas_si_test_fail_run_insert",
        )

    def test_invalid_audit_checkpoint_fails_closed_before_key_insert(self):
        tenant_id = self._tenant()
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO jas_si_audit_chain_state (singleton, last_hash)
                    VALUES (TRUE, %s)
                    ON CONFLICT (singleton) DO NOTHING
                    """,
                    ("0" * 64,),
                )
                cursor.execute(
                    """
                    UPDATE jas_si_audit_chain_state
                    SET last_hash = %s
                    WHERE singleton = TRUE
                    """,
                    ("f" * 64,),
                )
        with self.assertRaises(ApiKeyError):
            self._issue(tenant_id, "test:invalid-audit-checkpoint")
        self.assertEqual(self._counts(), (0, 0, 0))

    def test_checkpoint_update_failure_rolls_back_all_writes(self):
        tenant_id = self._tenant()
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE OR REPLACE FUNCTION jas_si_test_fail_checkpoint_update()
                    RETURNS trigger
                    LANGUAGE plpgsql
                    AS $$
                    BEGIN
                        RAISE EXCEPTION 'injected checkpoint update failure';
                    END;
                    $$
                    """
                )
                cursor.execute(
                    """
                    CREATE TRIGGER jas_si_test_fail_checkpoint_update
                    BEFORE UPDATE ON jas_si_audit_chain_state
                    FOR EACH ROW
                    EXECUTE FUNCTION jas_si_test_fail_checkpoint_update()
                    """
                )

        try:
            with self.assertRaises(ApiKeyError):
                self._issue(tenant_id, "test:checkpoint-failure")
        finally:
            with psycopg.connect(self.dsn) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "DROP TRIGGER IF EXISTS "
                        "jas_si_test_fail_checkpoint_update "
                        "ON jas_si_audit_chain_state"
                    )
                    cursor.execute(
                        "DROP FUNCTION IF EXISTS "
                        "jas_si_test_fail_checkpoint_update()"
                    )

        self.assertEqual(self._counts(), (0, 0, 0))
        result = PostgresSecurityEventStore(self.dsn).verify_integrity()
        self.assertTrue(result["valid"])
        self.assertEqual(result["verified_event_count"], 0)

    def test_concurrent_duplicate_run_id_commits_exactly_once(self):
        tenant_id = self._tenant()

        def issue():
            try:
                self._issue(tenant_id, "test:concurrent-duplicate")
                return "issued"
            except ApiKeyError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: issue(), range(2)))

        self.assertEqual(outcomes.count("issued"), 1)
        self.assertEqual(outcomes.count("rejected"), 1)
        self.assertEqual(self._counts(), (1, 1, 1))
        self.assertTrue(
            PostgresSecurityEventStore(self.dsn).verify_integrity()["valid"]
        )

    def test_duplicate_run_id_cannot_create_second_key(self):
        tenant_id = self._tenant()
        self._issue(tenant_id, "test:duplicate")
        with self.assertRaises(ApiKeyError):
            self._issue(tenant_id, "test:duplicate")
        self.assertEqual(self._counts(), (1, 1, 1))
        self.assertTrue(
            PostgresSecurityEventStore(self.dsn).verify_integrity()["valid"]
        )

    def test_database_role_grants_are_least_privilege_when_roles_exist(self):
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        EXISTS (SELECT 1 FROM pg_roles
                                WHERE rolname = 'jas_si_provisioner'),
                        EXISTS (SELECT 1 FROM pg_roles
                                WHERE rolname = 'jas_si_runtime')
                    """
                )
                provisioner_exists, runtime_exists = cursor.fetchone()

                if provisioner_exists:
                    cursor.execute(
                        """
                        SELECT
                            has_table_privilege(
                                'jas_si_provisioner',
                                'jas_si_api_key_provisioning_runs',
                                'SELECT'
                            ),
                            has_table_privilege(
                                'jas_si_provisioner',
                                'jas_si_api_key_provisioning_runs',
                                'INSERT'
                            )
                        """
                    )
                    self.assertEqual(
                        cursor.fetchone(),
                        (True, True),
                    )

                if provisioner_exists:
                    cursor.execute(
                        """
                        SELECT
                            has_column_privilege(
                                'jas_si_provisioner',
                                'jas_si_tenants',
                                'provisioning_lock_version',
                                'UPDATE'
                            ),
                            has_column_privilege(
                                'jas_si_provisioner',
                                'jas_si_tenants',
                                'status',
                                'UPDATE'
                            )
                        """
                    )
                    self.assertEqual(cursor.fetchone(), (True, False))

                if runtime_exists:
                    cursor.execute(
                        """
                        SELECT has_table_privilege(
                            'jas_si_runtime',
                            'jas_si_api_key_provisioning_runs',
                            'INSERT'
                        )
                        """
                    )
                    self.assertFalse(cursor.fetchone()[0])

    def _api_client(self):
        from jas_si_agent import api

        configured = replace(
            api.settings,
            environment="preview",
            api_enabled=True,
            api_key=None,
            api_key_pepper=self.pepper,
            database_url=self.dsn,
        )
        settings_patch = patch.object(api, "settings", configured)
        settings_patch.start()
        self.addCleanup(settings_patch.stop)
        store_patch = patch.object(
            api.app.state,
            "security_event_store",
            PostgresSecurityEventStore(self.dsn),
        )
        store_patch.start()
        self.addCleanup(store_patch.stop)
        with api._rate_limit_lock:
            api._rate_limit_buckets.clear()
        return TestClient(api.app)

    def test_real_registry_missing_key_returns_401(self):
        self._tenant()
        response = self._api_client().post(
            "/v1/verify",
            json={"action_id": "negative-missing", "claimed_success": True},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Missing or invalid API key")

    def test_real_registry_invalid_key_returns_401(self):
        self._tenant()
        response = self._api_client().post(
            "/v1/verify",
            headers={"X-API-Key": "jassi_live_invalid"},
            json={"action_id": "negative-invalid", "claimed_success": True},
        )
        self.assertEqual(response.status_code, 401)

    def test_real_registry_wrong_scope_returns_403(self):
        tenant_id = self._tenant()
        issued = self.registry.issue_key_with_audit(
            tenant_id=tenant_id,
            key_name="wrong-scope-test",
            scopes=["authorization:check"],
            created_by="integration-test-operator",
            provisioning_run_id="test:api-wrong-scope",
        )
        response = self._api_client().post(
            "/v1/verify",
            headers={"X-API-Key": issued.token},
            json={"action_id": "negative-scope", "claimed_success": True},
        )
        self.assertEqual(response.status_code, 403)

    def test_real_registry_valid_scope_authenticates(self):
        tenant_id = self._tenant()
        issued = self.registry.issue_key_with_audit(
            tenant_id=tenant_id,
            key_name="valid-scope-test",
            scopes=["outcomes:submit"],
            created_by="integration-test-operator",
            provisioning_run_id="test:api-valid-scope",
        )
        response = self._api_client().post(
            "/v1/verify",
            headers={"X-API-Key": issued.token},
            json={"action_id": "positive-valid", "claimed_success": True},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "INCONCLUSIVE")

    def test_revocation_and_audit_commit_together(self):
        tenant_id = self._tenant()
        issued = self._issue(tenant_id, "test:revoke-success")
        revoked = self.registry.revoke_key_with_audit(
            issued.key_id,
            "integration-test-operator",
            "test:revoke-success-run",
        )
        self.assertTrue(revoked)
        self.assertIsNone(self.registry.authenticate(issued.token))
        self.assertTrue(
            PostgresSecurityEventStore(self.dsn).verify_integrity()["valid"]
        )
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT event_payload->>'event_type'
                    FROM jas_si_audit_events
                    ORDER BY event_id
                    """
                )
                event_types = [row[0] for row in cursor.fetchall()]
        self.assertEqual(
            event_types,
            ["api_key_issued", "api_key_revoked"],
        )

    def test_revocation_audit_failure_rolls_back_key_status(self):
        tenant_id = self._tenant()
        issued = self._issue(tenant_id, "test:revoke-rollback")
        original = PostgresSecurityEventStore.append_in_transaction

        def append_then_fail(connection, event):
            original(connection, event)
            raise RuntimeError("injected revocation audit failure")

        with patch.object(
            PostgresSecurityEventStore,
            "append_in_transaction",
            side_effect=append_then_fail,
        ):
            with self.assertRaises(ApiKeyError):
                self.registry.revoke_key_with_audit(
                    issued.key_id,
                    "integration-test-operator",
                    "test:revoke-rollback-run",
                )

        self.assertIsNotNone(self.registry.authenticate(issued.token))
        self.assertTrue(
            PostgresSecurityEventStore(self.dsn).verify_integrity()["valid"]
        )
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT count(*)
                    FROM jas_si_audit_events
                    WHERE event_payload->>'event_type' = 'api_key_revoked'
                    """
                )
                self.assertEqual(cursor.fetchone()[0], 0)

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
