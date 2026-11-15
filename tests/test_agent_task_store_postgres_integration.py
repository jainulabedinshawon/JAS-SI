"""PostgreSQL integration tests for durable tenant-scoped agent tasks."""
from __future__ import annotations

import hashlib
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
except ImportError:
    psycopg = None

from jas_si_agent.agent_task_store import (
    AgentTaskIdempotencyConflict,
    AgentTaskStoreError,
    PostgresAgentTaskStore,
)


@unittest.skipUnless(DATABASE_URL and psycopg is not None, "PostgreSQL integration database is not configured")
class TestPostgresAgentTaskStore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn = DATABASE_URL
        migration_dir = ROOT / "src" / "jas_si_agent" / "migrations"
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
            "20261110_customer_rate_limits.sql",
            "20261110_usage_metering.sql",
            "20261110_usage_idempotency_fingerprint.sql",
            "20261111_usage_append_only_role_grants.sql",
            "20261114_customer_usage_read_routines.sql",
            "20261115_api_key_auth_boundary.sql",
            "20261116_api_key_bound_usage_routines.sql",
            "20261117_runtime_usage_routine_only.sql",
            "20261118_shared_api_rate_limits.sql",
            "20261119_general_runtime_customer_identity_acl.sql",
            "20261120_api_key_auth_runtime_tenant_acl.sql",
            "20261121_security_audit_writer_boundary.sql",
            "20261122_customer_rate_limit_owner_boundary.sql",
            "20261123_agent_task_store.sql",
        )
        with psycopg.connect(cls.dsn) as connection, connection.cursor() as cursor:
            for role in ("jas_si_runtime", "jas_si_provisioner", "jas_si_customer_runtime"):
                cursor.execute("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s", (role,))
                if cursor.fetchone() is None:
                    cursor.execute(f'CREATE ROLE "{role}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT')
            for name in migrations:
                cursor.execute((migration_dir / name).read_text(encoding="utf-8"))
        cls.store = PostgresAgentTaskStore(cls.dsn)

    def setUp(self):
        self.tenant_a, self.tenant_b = uuid.uuid4(), uuid.uuid4()
        self.key_a, self.key_b = uuid.uuid4(), uuid.uuid4()
        self.digest_a, self.digest_b = b"a" * 32, b"b" * 32
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            for tenant_id in (self.tenant_a, self.tenant_b):
                cursor.execute(
                    "INSERT INTO public.jas_si_tenants(tenant_id,tenant_name) VALUES (%s,%s)",
                    (tenant_id, f"task-test-{tenant_id}"),
                )
            for key_id, tenant_id, digest in (
                (self.key_a, self.tenant_a, self.digest_a),
                (self.key_b, self.tenant_b, self.digest_b),
            ):
                cursor.execute(
                    """INSERT INTO public.jas_si_api_keys
                       (key_id,tenant_id,key_name,key_prefix,secret_digest,scopes,created_by)
                       VALUES (%s,%s,'task integration','tasktest',%s,
                         ARRAY['agent:tasks:read','agent:tasks:write'],'ci')""",
                    (key_id, tenant_id, digest),
                )

    def _create(self, **overrides):
        values = dict(
            api_key_id=self.key_a, candidate_digest=self.digest_a,
            idempotency_key=f"task-{uuid.uuid4().hex}",
            task_type="agent.request",
            input_payload={"goal":"inspect repository","locale":"en"},
        )
        values.update(overrides)
        return self.store.create(**values)

    def test_create_persists_queued_task(self):
        submission = self._create()
        self.assertTrue(submission.created)
        self.assertEqual(submission.task.status, "queued")
        self.assertEqual(submission.task.input_payload["goal"], "inspect repository")
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM public.jas_si_agent_tasks WHERE task_id=%s", (submission.task.task_id,))
            self.assertEqual(cursor.fetchone()[0], 1)

    def test_idempotent_replay_returns_same_task(self):
        key = f"idem-{uuid.uuid4().hex}"
        first = self._create(idempotency_key=key)
        second = self._create(idempotency_key=key)
        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertEqual(first.task.task_id, second.task.task_id)

    def test_idempotency_conflict_rejected(self):
        key = f"conflict-{uuid.uuid4().hex}"
        self._create(idempotency_key=key, input_payload={"goal":"one"})
        with self.assertRaises(AgentTaskIdempotencyConflict):
            self._create(idempotency_key=key, input_payload={"goal":"two"})

    def test_tenant_cannot_read_or_cancel_another_tenant_task(self):
        submission = self._create()
        other = self.store.get(
            api_key_id=self.key_b,candidate_digest=self.digest_b,
            task_id=submission.task.task_id,
        )
        self.assertIsNone(other)
        self.assertFalse(self.store.cancel(
            api_key_id=self.key_b,candidate_digest=self.digest_b,
            task_id=submission.task.task_id,
        ))
        self.assertEqual(self.store.get(
            api_key_id=self.key_a,candidate_digest=self.digest_a,
            task_id=submission.task.task_id,
        ).status, "queued")

    def test_cancel_is_tenant_scoped_and_terminal(self):
        submission = self._create()
        self.assertTrue(self.store.cancel(
            api_key_id=self.key_a,candidate_digest=self.digest_a,
            task_id=submission.task.task_id,
        ))
        self.assertEqual(self.store.get(
            api_key_id=self.key_a,candidate_digest=self.digest_a,
            task_id=submission.task.task_id,
        ).status, "cancelled")
        self.assertFalse(self.store.cancel(
            api_key_id=self.key_a,candidate_digest=self.digest_a,
            task_id=submission.task.task_id,
        ))

    def test_invalid_or_inactive_key_is_rejected(self):
        with self.assertRaises(AgentTaskStoreError):
            self._create(candidate_digest=b"x" * 32)

    def test_direct_application_role_table_access_is_denied(self):
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT
                     has_table_privilege('jas_si_runtime','public.jas_si_agent_tasks','SELECT'),
                     has_table_privilege('jas_si_runtime','public.jas_si_agent_tasks','INSERT'),
                     has_table_privilege('jas_si_provisioner','public.jas_si_agent_tasks','UPDATE')"""
            )
            self.assertEqual(cursor.fetchone(), (False,False,False))

    def test_input_validation_rejects_non_json_and_oversized_payloads(self):
        with self.assertRaises(ValueError):
            self._create(input_payload={"bad":float("nan")})
        with self.assertRaises(ValueError):
            self._create(input_payload={"large":"x"*70000})

if __name__ == "__main__":
    unittest.main()
