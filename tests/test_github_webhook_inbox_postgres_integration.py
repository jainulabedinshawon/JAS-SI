"""PostgreSQL integration tests for the durable GitHub webhook inbox."""
import hashlib
import json
import os
import unittest
import uuid

import psycopg


def _payload(action="created", installation_id=183349938):
    return {
        "action": action,
        "installation": {"id": installation_id},
        "sender": {"login": "untrusted-sender"},
        "tenant_id": "must-never-be-used-as-authority",
    }


def _receive(conn, delivery_id, payload=None):
    payload = payload or _payload()
    raw = json.dumps(payload, separators=(",", ":")).encode()
    digest = hashlib.sha256(raw).digest()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT delivery_id,status,attempt_count,inserted
              FROM public.jas_si_github_webhook_receive(
                %s,%s,%s,%s,%s,%s::jsonb
              )
            """,
            (
                delivery_id,
                "installation",
                payload["action"],
                payload["installation"]["id"],
                digest,
                json.dumps(payload),
            ),
        )
        return cur.fetchone()


@unittest.skipUnless(
    os.environ.get("JAS_SI_MIGRATION_REPLAY_DATABASE_URL"),
    "PostgreSQL migration replay DSN is not configured",
)
class GitHubWebhookInboxPostgresTests(unittest.TestCase):
    def setUp(self):
        self.conn = psycopg.connect(os.environ["JAS_SI_MIGRATION_REPLAY_DATABASE_URL"])
        with self.conn.cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION jas_si_agent_runtime_test")
            cur.execute("SET ROLE jas_si_runtime")

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def test_receive_is_durable_and_delivery_id_is_idempotent(self):
        delivery_id = "it-" + uuid.uuid4().hex
        self.assertEqual(
            _receive(self.conn, delivery_id),
            (delivery_id, "RECEIVED", 0, True),
        )
        self.assertEqual(
            _receive(self.conn, delivery_id),
            (delivery_id, "RECEIVED", 0, False),
        )

        changed = _payload(action="suspend")
        with self.assertRaises(psycopg.Error):
            _receive(self.conn, delivery_id, changed)
        self.conn.rollback()

    def test_claim_failure_retry_and_success_are_distinct_states(self):
        delivery_id = "it-" + uuid.uuid4().hex
        _receive(self.conn, delivery_id)
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT delivery_id,event_name,action,installation_id,payload,attempt_count
                  FROM public.jas_si_github_webhook_claim(5,30)
                 WHERE delivery_id=%s
                """,
                (delivery_id,),
            )
            claimed = cur.fetchone()
            self.assertIsNotNone(claimed)
            self.assertEqual(claimed[0], delivery_id)
            self.assertEqual(claimed[1:4], ("installation", "created", 183349938))
            self.assertEqual(claimed[5], 1)

            cur.execute(
                "SELECT public.jas_si_github_webhook_mark_failed(%s,'API_UNAVAILABLE',5)",
                (delivery_id,),
            )
            self.assertIs(cur.fetchone()[0], True)

            # Test owner moves retry eligibility forward without sleeping.
            cur.execute("RESET SESSION AUTHORIZATION")
            cur.execute(
                """
                UPDATE public.jas_si_github_webhook_inbox
                   SET next_attempt_at=clock_timestamp()
                 WHERE delivery_id=%s
                """,
                (delivery_id,),
            )
            cur.execute("SET SESSION AUTHORIZATION jas_si_agent_runtime_test")
            cur.execute("SET ROLE jas_si_runtime")

            cur.execute(
                """
                SELECT delivery_id,attempt_count
                  FROM public.jas_si_github_webhook_claim(5,30)
                 WHERE delivery_id=%s
                """,
                (delivery_id,),
            )
            self.assertEqual(cur.fetchone(), (delivery_id, 2))
            cur.execute(
                "SELECT public.jas_si_github_webhook_mark_processed(%s)",
                (delivery_id,),
            )
            self.assertIs(cur.fetchone()[0], True)
            cur.execute(
                "SELECT public.jas_si_github_webhook_mark_failed(%s,'LATE_FAILURE',5)",
                (delivery_id,),
            )
            self.assertIs(cur.fetchone()[0], False)
            cur.execute(
                """
                SELECT delivery_id
                  FROM public.jas_si_github_webhook_claim(5,30)
                 WHERE delivery_id=%s
                """,
                (delivery_id,),
            )
            self.assertIsNone(cur.fetchone())

    def test_expired_processing_lease_can_be_reclaimed(self):
        delivery_id = "it-" + uuid.uuid4().hex
        _receive(self.conn, delivery_id)
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT delivery_id
                  FROM public.jas_si_github_webhook_claim(5,30)
                 WHERE delivery_id=%s
                """,
                (delivery_id,),
            )
            self.assertEqual(cur.fetchone(), (delivery_id,))
            cur.execute("RESET SESSION AUTHORIZATION")
            cur.execute(
                """
                UPDATE public.jas_si_github_webhook_inbox
                   SET lease_expires_at=clock_timestamp()-interval '1 second'
                 WHERE delivery_id=%s
                """,
                (delivery_id,),
            )
            cur.execute("SET SESSION AUTHORIZATION jas_si_agent_runtime_test")
            cur.execute("SET ROLE jas_si_runtime")
            cur.execute(
                """
                SELECT delivery_id,attempt_count
                  FROM public.jas_si_github_webhook_claim(5,30)
                 WHERE delivery_id=%s
                """,
                (delivery_id,),
            )
            self.assertEqual(cur.fetchone(), (delivery_id, 2))

    def test_runtime_cannot_read_inbox_table_directly(self):
        with self.conn.cursor() as cur:
            with self.assertRaises(psycopg.Error) as error:
                cur.execute("SELECT delivery_id FROM public.jas_si_github_webhook_inbox")
            self.assertEqual(error.exception.sqlstate, "42501")
            self.conn.rollback()


if __name__ == "__main__":
    unittest.main(verbosity=2)
