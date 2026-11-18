"""Real PostgreSQL privilege-boundary smoke test for agent-host preflight."""
from __future__ import annotations

import os
import sys

import psycopg

sys.path.insert(0, "src")
from jas_si_agent.agent_task_host_preflight import (  # noqa: E402
    AgentHostPreflightError,
    verify_agent_host_database_access,
)

WORKER_FUNCTIONS = (
    "public.jas_si_agent_task_claim(uuid,integer)",
    "public.jas_si_agent_task_renew(uuid,uuid,bigint,integer)",
    "public.jas_si_agent_task_ack_cancel(uuid,uuid,bigint)",
    "public.jas_si_agent_task_report(uuid,uuid,bigint,jsonb)",
    "public.jas_si_agent_task_fail(uuid,uuid,bigint,text,integer)",
)
VERIFIER_FUNCTIONS = (
    "public.jas_si_agent_task_verification_claim(integer,integer)",
    "public.jas_si_agent_task_verification_release(uuid,uuid,uuid)",
    "public.jas_si_agent_task_finalize_success(uuid,uuid,uuid,uuid,text,bytea,jsonb,timestamptz)",
)

ADMIN_DSN = os.environ["JAS_SI_TEST_ADMIN_DSN"]
WORKER_DSN = os.environ["JAS_SI_TEST_WORKER_DSN"]
VERIFIER_DSN = os.environ["JAS_SI_TEST_VERIFIER_DSN"]


def setup_database() -> None:
    with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE ROLE jas_si_agent_worker NOLOGIN NOINHERIT")
            cur.execute("CREATE ROLE jas_si_agent_verifier NOLOGIN NOINHERIT")
            cur.execute(
                "CREATE ROLE jas_si_agent_worker_login LOGIN NOINHERIT "
                "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS "
                "PASSWORD 'worker-test-only'"
            )
            cur.execute(
                "CREATE ROLE jas_si_agent_verifier_login LOGIN NOINHERIT "
                "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS "
                "PASSWORD 'verifier-test-only'"
            )
            cur.execute("GRANT jas_si_agent_worker TO jas_si_agent_worker_login")
            cur.execute("GRANT jas_si_agent_verifier TO jas_si_agent_verifier_login")
            cur.execute(
                "CREATE TABLE public.jas_si_agent_tasks "
                "(task_id uuid PRIMARY KEY, payload jsonb NOT NULL DEFAULT '{}'::jsonb)"
            )
            cur.execute(
                "CREATE TABLE public.jas_si_agent_evidence_records "
                "(evidence_id uuid PRIMARY KEY, task_id uuid NOT NULL, payload jsonb)"
            )
            for signature in WORKER_FUNCTIONS + VERIFIER_FUNCTIONS:
                name, args = signature.removeprefix("public.").split("(", 1)
                args = args[:-1]
                cur.execute(
                    f"CREATE FUNCTION public.{name}({args}) RETURNS void "
                    "LANGUAGE plpgsql AS $$ BEGIN RETURN; END $$"
                )
                cur.execute(
                    f"GRANT EXECUTE ON FUNCTION public.{name}({args}) "
                    "TO jas_si_agent_worker, jas_si_agent_verifier"
                )


def expect_denied(label: str, dsn: str, role: str, login: str, routines: tuple[str, ...]) -> None:
    try:
        verify_agent_host_database_access(
            dsn,
            capability_role=role,
            expected_login=login,
            required_functions=routines,
        )
    except AgentHostPreflightError:
        print(f"PASS: {label} rejected by real PostgreSQL privilege inspection")
        return
    raise SystemExit(f"FAIL: {label} was not rejected")


def main() -> None:
    setup_database()
    verify_agent_host_database_access(
        WORKER_DSN,
        capability_role="jas_si_agent_worker",
        expected_login="jas_si_agent_worker_login",
        required_functions=WORKER_FUNCTIONS,
    )
    print("PASS: least-privilege Worker login and routine grants accepted")
    verify_agent_host_database_access(
        VERIFIER_DSN,
        capability_role="jas_si_agent_verifier",
        expected_login="jas_si_agent_verifier_login",
        required_functions=VERIFIER_FUNCTIONS,
    )
    print("PASS: least-privilege Verifier login and routine grants accepted")

    with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "GRANT INSERT ON public.jas_si_agent_tasks TO jas_si_agent_verifier"
            )
    expect_denied(
        "Verifier task-table INSERT",
        VERIFIER_DSN,
        "jas_si_agent_verifier",
        "jas_si_agent_verifier_login",
        VERIFIER_FUNCTIONS,
    )
    with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "REVOKE INSERT ON public.jas_si_agent_tasks FROM jas_si_agent_verifier"
            )
            cur.execute(
                "GRANT SELECT (task_id) ON public.jas_si_agent_tasks "
                "TO jas_si_agent_verifier"
            )
    expect_denied(
        "Verifier task-table column SELECT",
        VERIFIER_DSN,
        "jas_si_agent_verifier",
        "jas_si_agent_verifier_login",
        VERIFIER_FUNCTIONS,
    )
    with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "REVOKE SELECT (task_id) ON public.jas_si_agent_tasks "
                "FROM jas_si_agent_verifier"
            )
            cur.execute(
                "GRANT UPDATE (payload) ON public.jas_si_agent_evidence_records "
                "TO jas_si_agent_verifier"
            )
    expect_denied(
        "Verifier evidence-table column UPDATE",
        VERIFIER_DSN,
        "jas_si_agent_verifier",
        "jas_si_agent_verifier_login",
        VERIFIER_FUNCTIONS,
    )
    with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "REVOKE UPDATE (payload) ON public.jas_si_agent_evidence_records "
                "FROM jas_si_agent_verifier"
            )
            cur.execute(
                "GRANT TRUNCATE ON public.jas_si_agent_tasks TO jas_si_agent_worker"
            )
    expect_denied(
        "Worker task-table TRUNCATE",
        WORKER_DSN,
        "jas_si_agent_worker",
        "jas_si_agent_worker_login",
        WORKER_FUNCTIONS,
    )
    print("PASS: all real PostgreSQL privilege-boundary smoke tests")


if __name__ == "__main__":
    main()
