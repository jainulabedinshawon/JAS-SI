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
from jas_si_agent.security_event_store import _event_hash


@unittest.skipUnless(
    DATABASE_URL and psycopg is not None,
    "PostgreSQL integration database is not configured",
)
class TestPostgresAuditIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.dsn = DATABASE_URL
        cls.store = PostgresSecurityEventStore(cls.dsn)

        migration = (
            ROOT
            / "src"
            / "jas_si_agent"
            / "migrations"
            / "001_create_audit_tables.sql"
        )

        with psycopg.connect(cls.dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    migration.read_text(encoding="utf-8")
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


if __name__ == "__main__":
    unittest.main()
