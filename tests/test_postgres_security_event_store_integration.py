from __future__ import annotations

import os
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

DATABASE_URL = os.getenv("JAS_SI_TEST_DATABASE_URL")

try:
    import psycopg
except ImportError:
    psycopg = None

from jas_si_agent.postgres_security_event_store import (
    GENESIS_HASH,
    PostgresSecurityEventStore,
)
from jas_si_agent.security_event_store import (
    SecurityEventStoreError,
    _event_hash,
)


@unittest.skipUnless(
    DATABASE_URL and psycopg is not None,
    "PostgreSQL integration database is not configured",
)
class TestPostgresAuditIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dsn = DATABASE_URL
        cls.store = PostgresSecurityEventStore(cls.dsn)

        migration_dir = ROOT / "src" / "jas_si_agent" / "migrations"
        required_roles = (
            "jas_si_runtime",
            "jas_si_provisioner",
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
            "007_customer_api_key_self_service.sql",
            "20261110_customer_identity.sql",
            "20261112_customer_identity_routines.sql",
            "20261113_customer_api_key_routines.sql",
            "20261115_api_key_auth_boundary.sql",
            "20261121_security_audit_writer_boundary.sql",
        )
        with psycopg.connect(cls.dsn) as connection, connection.cursor() as cursor:
            for role in required_roles:
                cursor.execute(
                    "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s",
                    (role,),
                )
                if cursor.fetchone() is None:
                    cursor.execute(f'CREATE ROLE "{role}" NOLOGIN')
            for name in migrations:
                cursor.execute(
                    (migration_dir / name).read_text(encoding="utf-8")
                )

    def setUp(self):
        # This database is dedicated to CI integration tests.
        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "TRUNCATE jas_si_audit_events RESTART IDENTITY"
                )
                cursor.execute(
                    "DELETE FROM jas_si_audit_chain_state"
                )

    def _append_events(self, count=3):
        for sequence in range(count):
            self.store.append({
                "event_type": "integration_test",
                "sequence": sequence,
            })

    def test_runtime_role_can_append_but_cannot_mutate_audit_tables(self):
        event = {"event_type": "runtime_boundary", "role": "jas_si_runtime"}
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET ROLE jas_si_runtime")
            cursor.execute(
                """SELECT has_table_privilege(current_user,
                          'public.jas_si_audit_chain_state','INSERT'),
                          has_table_privilege(current_user,
                          'public.jas_si_audit_chain_state','UPDATE'),
                          has_table_privilege(current_user,
                          'public.jas_si_audit_events','INSERT')"""
            )
            self.assertEqual(cursor.fetchone(), (False, False, False))
            PostgresSecurityEventStore.append_in_transaction(connection, event)

        result = self.store.verify_integrity()
        self.assertTrue(result["valid"])
        self.assertEqual(result["verified_event_count"], 1)

    def test_runtime_role_can_verify_audit_chain_with_canonicalizer(self):
        self._append_events(2)

        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET ROLE jas_si_runtime")
            result = PostgresSecurityEventStore.verify_integrity_in_transaction(
                connection
            )

        self.assertTrue(result["valid"])
        self.assertEqual(result["verified_event_count"], 2)

    def test_empty_database_has_valid_genesis_state(self):
        result = self.store.verify_integrity()

        self.assertTrue(result["valid"])
        self.assertEqual(result["verified_event_count"], 0)
        self.assertEqual(result["last_hash"], GENESIS_HASH)

    def test_real_database_persists_event_and_checkpoint(self):
        event = {
            "event_type": "integration_test",
            "allowed": True,
            "sequence": 1,
        }

        self.store.append(event)

        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT event_payload, previous_hash, event_hash
                    FROM jas_si_audit_events
                    ORDER BY event_id
                    """
                )
                row = cursor.fetchone()

                cursor.execute(
                    """
                    SELECT last_hash
                    FROM jas_si_audit_chain_state
                    WHERE singleton = TRUE
                    """
                )
                checkpoint = cursor.fetchone()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], event)
        self.assertEqual(row[1], GENESIS_HASH)

        expected_hash = _event_hash(event, GENESIS_HASH)

        self.assertEqual(row[2], expected_hash)
        self.assertEqual(checkpoint[0], expected_hash)

    def test_read_side_verifier_accepts_valid_chain(self):
        self._append_events(5)

        result = self.store.verify_integrity()

        self.assertTrue(result["valid"])
        self.assertEqual(result["verified_event_count"], 5)

    def test_jsonb_numeric_and_unicode_values_verify(self):
        self.store.append({
            "event_type": "jsonb_roundtrip",
            "integer_value": 1,
            "float_value": 1.0,
            "small_float": 1e-7,
            "unicode": "বাংলা — JAS-SI",
            "nested": {
                "enabled": True,
                "values": [1, 2.5, "verified"],
            },
        })

        result = self.store.verify_integrity()

        self.assertTrue(result["valid"])
        self.assertEqual(result["verified_event_count"], 1)

    def test_payload_tampering_is_detected(self):
        self._append_events(2)

        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE jas_si_audit_events
                    SET event_payload = jsonb_set(
                        event_payload,
                        '{sequence}',
                        '999'::jsonb
                    )
                    WHERE event_id = 1
                    """
                )

        with self.assertRaises(SecurityEventStoreError):
            self.store.verify_integrity()

    def test_middle_event_deletion_is_detected(self):
        self._append_events(3)

        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    DELETE FROM jas_si_audit_events
                    WHERE event_id = 2
                    """
                )

        with self.assertRaises(SecurityEventStoreError):
            self.store.verify_integrity()

    def test_checkpoint_tampering_is_detected(self):
        self._append_events(2)

        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE jas_si_audit_chain_state
                    SET last_hash = %s
                    WHERE singleton = TRUE
                    """,
                    ("f" * 64,),
                )

        with self.assertRaises(SecurityEventStoreError):
            self.store.verify_integrity()

    def test_missing_checkpoint_with_events_is_detected(self):
        self._append_events(1)

        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM jas_si_audit_chain_state"
                )

        with self.assertRaises(SecurityEventStoreError):
            self.store.verify_integrity()

    def test_concurrent_writes_preserve_hash_chain(self):
        worker_count = 4
        events_per_worker = 10
        barrier = threading.Barrier(worker_count)

        def write_events(worker_id):
            barrier.wait(timeout=10)

            for sequence in range(events_per_worker):
                self.store.append({
                    "event_type": "concurrent_integration_test",
                    "worker_id": worker_id,
                    "sequence": sequence,
                })

        with ThreadPoolExecutor(
            max_workers=worker_count
        ) as executor:
            futures = [
                executor.submit(write_events, worker_id)
                for worker_id in range(worker_count)
            ]

            for future in futures:
                future.result(timeout=60)

        with psycopg.connect(self.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT event_payload, previous_hash, event_hash
                    FROM jas_si_audit_events
                    ORDER BY event_id
                    """
                )
                rows = cursor.fetchall()

                cursor.execute(
                    """
                    SELECT last_hash
                    FROM jas_si_audit_chain_state
                    WHERE singleton = TRUE
                    """
                )
                checkpoint = cursor.fetchone()

        expected_count = worker_count * events_per_worker
        self.assertEqual(len(rows), expected_count)

        previous_hash = GENESIS_HASH

        for payload, recorded_previous, recorded_hash in rows:
            self.assertEqual(recorded_previous, previous_hash)

            expected_hash = _event_hash(payload, previous_hash)
            self.assertEqual(recorded_hash, expected_hash)

            previous_hash = expected_hash

        self.assertEqual(checkpoint[0], previous_hash)

        verification = self.store.verify_integrity()
        self.assertTrue(verification["valid"])
        self.assertEqual(
            verification["verified_event_count"],
            expected_count,
        )


if __name__ == "__main__":
    unittest.main()
