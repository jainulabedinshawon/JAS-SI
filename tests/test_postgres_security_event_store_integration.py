from __future__ import annotations

import hashlib
import os
import sys
import threading
import unittest
import uuid
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
from jas_si_agent.agent_task_store import (
    AgentTaskIdempotencyConflict,
    AgentTaskStoreError,
    PostgresAgentTaskStore,
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

    def _append_events(self, count=3):
        for sequence in range(count):
            self.store.append({
                "event_type": "integration_test",
                "sequence": sequence,
            })

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



# Durable task-store integration tests share this established PostgreSQL CI job.
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
            "20261123_agent_task_store.sql",
            "20261123_agent_task_scope_allowlist.sql",
            "20261124_agent_task_worker_lifecycle.sql",
        )
        with psycopg.connect(cls.dsn) as connection, connection.cursor() as cursor:
            for role in ("jas_si_runtime", "jas_si_provisioner", "jas_si_customer_runtime"):
                cursor.execute("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s", (role,))
                if cursor.fetchone() is None:
                    cursor.execute(f'CREATE ROLE "{role}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT')
            for name in migrations:
                cursor.execute((migration_dir / name).read_text(encoding="utf-8"))
            # The task-store migration must be safe to replay without losing data.
            cursor.execute((migration_dir / "20261123_agent_task_store.sql").read_text(encoding="utf-8"))
        with psycopg.connect(cls.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("GRANT jas_si_agent_worker TO jas_si")
        cls.store = PostgresAgentTaskStore(cls.dsn)

    def setUp(self):
        self.tenant_a, self.tenant_b = uuid.uuid4(), uuid.uuid4()
        self.key_a, self.key_b = uuid.uuid4(), uuid.uuid4()
        self.digest_a, self.digest_b = b"a" * 32, b"b" * 32
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("DELETE FROM public.jas_si_agent_tasks")
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
                       VALUES (%s,%s,'task integration',%s,%s,
                         ARRAY['agent:tasks:read','agent:tasks:write'],'ci')""",
                    (key_id, tenant_id, f"tasktest_{uuid.uuid4().hex}", digest),
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

    def test_idempotency_hash_covers_task_type_and_retry_policy(self):
        key = f"request-hash-{uuid.uuid4().hex}"
        self._create(idempotency_key=key, task_type="agent.inspect", max_attempts=2)
        with self.assertRaises(AgentTaskIdempotencyConflict):
            self._create(idempotency_key=key, task_type="agent.execute", max_attempts=2)
        with self.assertRaises(AgentTaskIdempotencyConflict):
            self._create(idempotency_key=key, task_type="agent.inspect", max_attempts=3)

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

    def test_running_task_cancellation_is_request_not_false_completion(self):
        submission = self._create()
        worker_id = f"worker-{uuid.uuid4().hex}"
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute(
                """UPDATE public.jas_si_agent_tasks
                      SET status='running',attempt_count=1,
                          lease_owner=%s,lease_expires_at=clock_timestamp()+interval '2 minutes'
                    WHERE task_id=%s""",
                (worker_id, submission.task.task_id),
            )

        self.assertTrue(self.store.cancel(
            api_key_id=self.key_a,candidate_digest=self.digest_a,
            task_id=submission.task.task_id,
        ))
        task = self.store.get(
            api_key_id=self.key_a,candidate_digest=self.digest_a,
            task_id=submission.task.task_id,
        )
        self.assertEqual(task.status, "cancel_requested")
        self.assertIsNone(task.completed_at)
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT lease_owner,lease_expires_at IS NOT NULL FROM public.jas_si_agent_tasks WHERE task_id=%s",
                (submission.task.task_id,),
            )
            self.assertEqual(cursor.fetchone(), (worker_id, True))

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

    def test_runtime_role_uses_scoped_task_routines_without_table_access(self):
        from psycopg.types.json import Jsonb

        task_id = uuid.uuid4()
        idempotency_key = f"runtime-{uuid.uuid4().hex}"
        payload = {"goal": "runtime role integration"}
        request_hash = hashlib.sha256(b"runtime-role-task").digest()

        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET ROLE jas_si_runtime")
            cursor.execute(
                """SELECT task_id,status,created
                   FROM public.jas_si_agent_task_create(
                     %s,%s,%s,%s,%s,%s,%s,%s)""",
                (task_id,self.key_a,self.digest_a,idempotency_key,request_hash,
                 "agent.request",Jsonb(payload),3),
            )
            created = cursor.fetchone()
            self.assertEqual(created, (task_id,"queued",True))

            cursor.execute(
                """SELECT task_id,status
                   FROM public.jas_si_agent_task_get(%s,%s,%s)""",
                (self.key_a,self.digest_a,task_id),
            )
            self.assertEqual(cursor.fetchone(), (task_id,"queued"))

            cursor.execute(
                "SELECT public.jas_si_agent_task_cancel(%s,%s,%s)",
                (self.key_a,self.digest_a,task_id),
            )
            self.assertTrue(cursor.fetchone()[0])

            cursor.execute(
                """SELECT task_id,status
                   FROM public.jas_si_agent_task_get(%s,%s,%s)""",
                (self.key_a,self.digest_a,task_id),
            )
            self.assertEqual(cursor.fetchone(), (task_id,"cancelled"))

            with self.assertRaises(psycopg.Error):
                cursor.execute(
                    "SELECT task_id FROM public.jas_si_agent_tasks WHERE task_id=%s",
                    (task_id,),
                )
            connection.rollback()

    def test_concurrent_idempotent_submissions_create_one_task(self):
        idempotency_key = f"concurrent-{uuid.uuid4().hex}"
        barrier = threading.Barrier(2)

        def submit():
            barrier.wait(timeout=10)
            return self._create(idempotency_key=idempotency_key)

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(submit) for _ in range(2)]
            submissions = [future.result(timeout=30) for future in futures]

        self.assertEqual(sum(item.created for item in submissions), 1)
        self.assertEqual(
            submissions[0].task.task_id,
            submissions[1].task.task_id,
        )
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM public.jas_si_agent_tasks WHERE tenant_id=%s AND idempotency_key=%s",
                (self.tenant_a, idempotency_key),
            )
            self.assertEqual(cursor.fetchone()[0], 1)

    def test_customer_key_issue_accepts_agent_task_scopes_before_session_auth(self):
        # Scope validation must accept the new task scopes, then fail only because
        # this isolated test deliberately supplies no live customer session.
        key_id = uuid.uuid4()
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET LOCAL ROLE jas_si_customer_key_owner")
            with self.assertRaises(psycopg.Error) as raised:
                cursor.execute(
                    """SELECT * FROM public.customer_api_key_issue(
                         %s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        b"s" * 32, key_id, "agent task test",
                        "jassi_live_" + key_id.hex,
                        b"d" * 32, 1,
                        ["agent:tasks:read", "agent:tasks:write"],
                        None, "scope-test-" + uuid.uuid4().hex,
                    ),
                )
        self.assertEqual(raised.exception.sqlstate, "28000")

    def test_input_validation_rejects_non_json_and_oversized_payloads(self):
        with self.assertRaises(ValueError):
            self._create(input_payload={"bad":float("nan")})
        with self.assertRaises(ValueError):
            self._create(input_payload={"large":"x"*70000})
    def _worker_call(self, sql, params):
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET ROLE jas_si_agent_worker")
            cursor.execute(sql, params)
            return cursor.fetchall()

    def test_worker_claim_is_atomic_and_fenced(self):
        task = self._create().task
        worker_id = uuid.uuid4()
        claimed = self._worker_call(
            "SELECT * FROM public.jas_si_agent_task_claim(%s,60)",
            (worker_id,),
        )
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0][0], task.task_id)
        self.assertEqual(claimed[0][3], 1)
        self.assertEqual(claimed[0][5], 1)
        self.assertEqual(self._worker_call(
            "SELECT * FROM public.jas_si_agent_task_claim(%s,60)",
            (uuid.uuid4(),),
        ), [])

    def test_worker_renewal_requires_current_fence(self):
        task = self._create().task
        worker_id = uuid.uuid4()
        claimed = self._worker_call(
            "SELECT * FROM public.jas_si_agent_task_claim(%s,60)", (worker_id,)
        )[0]
        self.assertEqual(self._worker_call(
            "SELECT public.jas_si_agent_task_renew(%s,%s,%s,60)",
            (worker_id, task.task_id, claimed[5]),
        ), [(True,)])
        self.assertEqual(self._worker_call(
            "SELECT public.jas_si_agent_task_renew(%s,%s,%s,60)",
            (worker_id, task.task_id, claimed[5] + 1),
        ), [(False,)])

    def test_stale_worker_cannot_report_after_reclaim(self):
        from psycopg.types.json import Jsonb
        task = self._create().task
        old_worker, new_worker = uuid.uuid4(), uuid.uuid4()
        old_claim = self._worker_call(
            "SELECT * FROM public.jas_si_agent_task_claim(%s,60)", (old_worker,)
        )[0]
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE public.jas_si_agent_tasks SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE task_id=%s",
                (task.task_id,),
            )
        new_claim = self._worker_call(
            "SELECT * FROM public.jas_si_agent_task_claim(%s,60)", (new_worker,)
        )[0]
        self.assertEqual(new_claim[5], old_claim[5] + 1)
        self.assertEqual(self._worker_call(
            "SELECT public.jas_si_agent_task_report(%s,%s,%s,%s)",
            (old_worker, task.task_id, old_claim[5], Jsonb({"claim":"success"})),
        ), [(False,)])
        self.assertEqual(self._worker_call(
            "SELECT public.jas_si_agent_task_report(%s,%s,%s,%s)",
            (new_worker, task.task_id, new_claim[5], Jsonb({"claim":"success"})),
        ), [(True,)])
        current = self.store.get(
            api_key_id=self.key_a,candidate_digest=self.digest_a,
            task_id=task.task_id,
        )
        self.assertEqual(current.status, "awaiting_verification")
        self.assertIsNone(current.completed_at)

    def test_worker_cancellation_requires_acknowledgement(self):
        task = self._create().task
        worker_id = uuid.uuid4()
        claim = self._worker_call(
            "SELECT * FROM public.jas_si_agent_task_claim(%s,60)", (worker_id,)
        )[0]
        self.assertTrue(self.store.cancel(
            api_key_id=self.key_a,candidate_digest=self.digest_a,task_id=task.task_id,
        ))
        self.assertEqual(self.store.get(
            api_key_id=self.key_a,candidate_digest=self.digest_a,task_id=task.task_id,
        ).status, "cancel_requested")
        self.assertEqual(self._worker_call(
            "SELECT public.jas_si_agent_task_ack_cancel(%s,%s,%s)",
            (worker_id,task.task_id,claim[5]),
        ), [(True,)])
        self.assertEqual(self.store.get(
            api_key_id=self.key_a,candidate_digest=self.digest_a,task_id=task.task_id,
        ).status, "cancelled")

    def test_expired_cancellation_is_terminal_and_never_requeued(self):
        task = self._create(max_attempts=3).task
        worker_id = uuid.uuid4()
        claim = self._worker_call(
            "SELECT * FROM public.jas_si_agent_task_claim(%s,60)", (worker_id,)
        )[0]
        self.assertTrue(self.store.cancel(
            api_key_id=self.key_a,candidate_digest=self.digest_a,task_id=task.task_id,
        ))
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE public.jas_si_agent_tasks SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE task_id=%s",
                (task.task_id,),
            )
        self.assertEqual(self._worker_call(
            "SELECT * FROM public.jas_si_agent_task_claim(%s,60)", (uuid.uuid4(),)
        ), [])
        current = self.store.get(
            api_key_id=self.key_a,candidate_digest=self.digest_a,task_id=task.task_id,
        )
        self.assertEqual(current.status, "failed")
        self.assertEqual(current.error_code, "WORKER_LOST_DURING_CANCELLATION")
        self.assertIsNotNone(current.completed_at)

    def test_worker_failure_retries_then_becomes_terminal(self):
        task = self._create(max_attempts=2).task
        worker_id = uuid.uuid4()
        first = self._worker_call(
            "SELECT * FROM public.jas_si_agent_task_claim(%s,60)", (worker_id,)
        )[0]
        self.assertEqual(self._worker_call(
            "SELECT public.jas_si_agent_task_fail(%s,%s,%s,%s,0)",
            (worker_id,task.task_id,first[5],"TRANSIENT_ERROR"),
        ), [("queued",)])
        second = self._worker_call(
            "SELECT * FROM public.jas_si_agent_task_claim(%s,60)", (worker_id,)
        )[0]
        self.assertEqual(second[3], 2)
        self.assertEqual(self._worker_call(
            "SELECT public.jas_si_agent_task_fail(%s,%s,%s,%s,0)",
            (worker_id,task.task_id,second[5],"TRANSIENT_ERROR"),
        ), [("failed",)])
        current = self.store.get(
            api_key_id=self.key_a,candidate_digest=self.digest_a,task_id=task.task_id,
        )
        self.assertEqual(current.status, "failed")
        self.assertIsNotNone(current.completed_at)

    def test_worker_role_cannot_be_used_without_capability_membership(self):
        # Public callers must not be able to invoke worker routines as runtime.
        with psycopg.connect(self.dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET ROLE jas_si_runtime")
            with self.assertRaises(psycopg.Error):
                cursor.execute(
                    "SELECT * FROM public.jas_si_agent_task_claim(%s,60)",
                    (uuid.uuid4(),),
                )
            connection.rollback()



if __name__ == "__main__":
    unittest.main()
