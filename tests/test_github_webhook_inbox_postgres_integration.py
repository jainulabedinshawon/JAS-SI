"""PostgreSQL integration tests for the durable GitHub webhook inbox."""
import hashlib
import json
import os
import sys
import unittest
import uuid
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.github_webhook_inbox import PostgresGitHubWebhookInbox


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
                SELECT delivery_id,event_name,action,installation_id,payload,attempt_count,claim_token
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
            first_claim_token = claimed[6]

            cur.execute(
                "SELECT public.jas_si_github_webhook_mark_failed(%s,'API_UNAVAILABLE',%s,5)",
                (delivery_id, first_claim_token),
            )
            self.assertIs(cur.fetchone()[0], True)

            # Test owner moves retry eligibility forward without sleeping.
            cur.execute("RESET ROLE")
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
                SELECT delivery_id,attempt_count,claim_token
                  FROM public.jas_si_github_webhook_claim(5,30)
                 WHERE delivery_id=%s
                """,
                (delivery_id,),
            )
            second_claim = cur.fetchone()
            self.assertEqual(second_claim[:2], (delivery_id, 2))
            second_claim_token = second_claim[2]
            self.assertNotEqual(first_claim_token, second_claim_token)
            cur.execute(
                "SELECT public.jas_si_github_webhook_mark_processed(%s,%s)",
                (delivery_id, second_claim_token),
            )
            self.assertIs(cur.fetchone()[0], True)
            cur.execute(
                "SELECT public.jas_si_github_webhook_mark_failed(%s,'LATE_FAILURE',%s,5)",
                (delivery_id, first_claim_token),
            )
            self.assertIs(cur.fetchone()[0], False)
            cur.execute(
                """
                SELECT delivery_id,claim_token
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
                SELECT delivery_id,claim_token
                  FROM public.jas_si_github_webhook_claim(5,30)
                 WHERE delivery_id=%s
                """,
                (delivery_id,),
            )
            first_claim = cur.fetchone()
            self.assertEqual(first_claim[0], delivery_id)
            stale_token = first_claim[1]
            cur.execute("RESET ROLE")
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
                SELECT delivery_id,attempt_count,claim_token
                  FROM public.jas_si_github_webhook_claim(5,30)
                 WHERE delivery_id=%s
                """,
                (delivery_id,),
            )
            reclaimed = cur.fetchone()
            self.assertEqual(reclaimed[:2], (delivery_id, 2))
            self.assertNotEqual(stale_token, reclaimed[2])
            cur.execute(
                "SELECT public.jas_si_github_webhook_mark_processed(%s,%s)",
                (delivery_id, stale_token),
            )
            self.assertIs(cur.fetchone()[0], False)


    def test_postgres_adapter_assumes_runtime_role_and_persists_delivery(self):
        delivery_id = "it-adapter-" + uuid.uuid4().hex
        payload = _payload()
        raw = json.dumps(payload, separators=(",", ":")).encode()
        receipt = PostgresGitHubWebhookInbox(
            os.environ["JAS_SI_MIGRATION_REPLAY_DATABASE_URL"]
        ).receive(
            delivery_id=delivery_id,
            event_name="installation",
            action="created",
            installation_id=payload["installation"]["id"],
            raw_body_sha256=hashlib.sha256(raw).digest(),
            payload=payload,
        )
        self.assertEqual(receipt.delivery_id, delivery_id)
        self.assertEqual(receipt.status, "RECEIVED")
        self.assertEqual(receipt.attempt_count, 0)
        self.assertTrue(receipt.inserted)

        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT delivery_id,attempt_count,claim_token
                  FROM public.jas_si_github_webhook_claim(5,30)
                 WHERE delivery_id=%s
                """,
                (delivery_id,),
            )
            claimed = cur.fetchone()
            self.assertEqual(claimed[:2], (delivery_id, 1))
            cur.execute(
                "SELECT public.jas_si_github_webhook_mark_processed(%s,%s)",
                (delivery_id, claimed[2]),
            )
            self.assertIs(cur.fetchone()[0], True)

    def test_runtime_cannot_read_inbox_table_directly(self):
        with self.conn.cursor() as cur:
            with self.assertRaises(psycopg.Error) as error:
                cur.execute("SELECT delivery_id FROM public.jas_si_github_webhook_inbox")
            self.assertEqual(error.exception.sqlstate, "42501")
            self.conn.rollback()


if __name__ == "__main__":
    unittest.main(verbosity=2)
