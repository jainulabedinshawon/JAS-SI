"""PostgreSQL integration tests for the durable GitHub webhook inbox."""
import hashlib
import json
import os
import uuid

import psycopg
import pytest


@pytest.fixture()
def runtime_connection():
    dsn = os.environ.get("JAS_SI_MIGRATION_REPLAY_DATABASE_URL")
    if not dsn:
        pytest.skip("PostgreSQL migration replay DSN is not configured")
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION jas_si_agent_runtime_test")
            cur.execute("SET ROLE jas_si_runtime")
        yield conn
        conn.rollback()


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


def test_receive_is_durable_and_delivery_id_is_idempotent(runtime_connection):
    delivery_id = "it-" + uuid.uuid4().hex
    first = _receive(runtime_connection, delivery_id)
    assert first == (delivery_id, "RECEIVED", 0, True)

    duplicate = _receive(runtime_connection, delivery_id)
    assert duplicate == (delivery_id, "RECEIVED", 0, False)

    changed = _payload(action="suspend")
    with pytest.raises(psycopg.Error):
        _receive(runtime_connection, delivery_id, changed)
    runtime_connection.rollback()


def test_claim_failure_retry_and_success_are_distinct_states(runtime_connection):
    delivery_id = "it-" + uuid.uuid4().hex
    _receive(runtime_connection, delivery_id)
    with runtime_connection.cursor() as cur:
        cur.execute(
            """
            SELECT delivery_id,event_name,action,installation_id,payload,attempt_count
              FROM public.jas_si_github_webhook_claim(5,30)
             WHERE delivery_id=%s
            """,
            (delivery_id,),
        )
        claimed = cur.fetchone()
        assert claimed is not None
        assert claimed[0] == delivery_id
        assert claimed[1:4] == ("installation", "created", 183349938)
        assert claimed[5] == 1

        cur.execute(
            "SELECT public.jas_si_github_webhook_mark_failed(%s,'API_UNAVAILABLE',5)",
            (delivery_id,),
        )
        assert cur.fetchone()[0] is True

        # A failed delivery is not treated as successfully processed. Move its
        # retry time forward using the migration-test owner connection below.
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
        retry = cur.fetchone()
        assert retry == (delivery_id, 2)
        cur.execute(
            "SELECT public.jas_si_github_webhook_mark_processed(%s)",
            (delivery_id,),
        )
        assert cur.fetchone()[0] is True
        cur.execute(
            "SELECT public.jas_si_github_webhook_mark_failed(%s,'LATE_FAILURE',5)",
            (delivery_id,),
        )
        assert cur.fetchone()[0] is False
        cur.execute(
            """
            SELECT delivery_id
              FROM public.jas_si_github_webhook_claim(5,30)
             WHERE delivery_id=%s
            """,
            (delivery_id,),
        )
        assert cur.fetchone() is None


def test_expired_processing_lease_can_be_reclaimed(runtime_connection):
    delivery_id = "it-" + uuid.uuid4().hex
    _receive(runtime_connection, delivery_id)
    with runtime_connection.cursor() as cur:
        cur.execute(
            """
            SELECT delivery_id
              FROM public.jas_si_github_webhook_claim(5,30)
             WHERE delivery_id=%s
            """,
            (delivery_id,),
        )
        assert cur.fetchone() == (delivery_id,)
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
        assert cur.fetchone() == (delivery_id, 2)


def test_runtime_cannot_read_inbox_table_directly(runtime_connection):
    with runtime_connection.cursor() as cur:
        with pytest.raises(psycopg.Error) as error:
            cur.execute("SELECT delivery_id FROM public.jas_si_github_webhook_inbox")
        assert error.value.sqlstate == "42501"
        runtime_connection.rollback()
