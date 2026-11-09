"""Idempotent cleanup for a single GitHub Actions staging smoke-test run."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import psycopg  # noqa: E402
from jas_si_agent.api_key_registry import (  # noqa: E402
    ApiKeyError,
    PostgresApiKeyRegistry,
)
from jas_si_agent.postgres_security_event_store import (  # noqa: E402
    PostgresSecurityEventStore,
)


def main() -> int:
    dsn = os.getenv("JAS_SI_PROVISIONER_DATABASE_URL", "")
    pepper = os.getenv("JAS_SI_API_KEY_PEPPER", "")
    run_id = os.getenv("GITHUB_RUN_ID", "")
    actor = os.getenv("GITHUB_ACTOR", "github-actions-cleanup")
    if not dsn or len(pepper.encode("utf-8")) < 32 or not run_id.isdigit():
        print("Cleanup configuration is invalid.")
        return 2

    provisioning_run_id = f"github-actions:{run_id}"
    try:
        print("cleanup_dsn_parse=START", flush=True)
        try:
            conninfo = psycopg.conninfo.conninfo_to_dict(dsn)
        except Exception as parse_exc:
            print("cleanup_dsn_parse=FAIL", flush=True)
            print("cleanup_dsn_parse_error_type=" + type(parse_exc).__name__, flush=True)
            parse_state = getattr(parse_exc, "sqlstate", None)
            if parse_state:
                print("cleanup_dsn_parse_sqlstate=" + parse_state, flush=True)
            raise
        print("cleanup_dsn_parse=PASS", flush=True)
        print(
            "cleanup_dsn_fields="
            + ",".join(sorted(k for k in conninfo if k in {"host", "port", "dbname", "user", "password", "sslmode"})),
            flush=True,
        )
        print(
            "cleanup_dsn_required_fields="
            + "".join("1" if conninfo.get(k) else "0" for k in ("host", "dbname", "user", "password")),
            flush=True,
        )
        registry = PostgresApiKeyRegistry(dsn, pepper.encode("utf-8"))
        print("cleanup_constructor=PASS")
        with psycopg.connect(dsn) as connection:
            print("cleanup_db_connect=PASS", flush=True)
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT current_database(),
                           to_regclass('public.jas_si_api_key_provisioning_runs') IS NOT NULL,
                           to_regclass('public.jas_si_api_keys') IS NOT NULL
                    """
                )
                print("cleanup_schema_query=PASS", flush=True)
                db_name, runs_ok, keys_ok = cursor.fetchone()
                print(f"cleanup_database_name={db_name}")
                print(f"cleanup_schema_preflight={int(runs_ok)}{int(keys_ok)}")
                if not (runs_ok and keys_ok):
                    raise RuntimeError("Staging cleanup schema preflight failed")
                cursor.execute(
                    """
                    SELECT k.key_id, k.status
                    FROM public.jas_si_api_key_provisioning_runs AS r
                    JOIN public.jas_si_api_keys AS k ON k.key_id = r.key_id
                    WHERE r.run_id = %s
                    """,
                    (provisioning_run_id,),
                )
                row = cursor.fetchone()

        if row is None:
            print("No key was created by this workflow run.")
            return 0

        key_id, status = row
        if status == "active":
            revoked = registry.revoke_key_with_audit(
                key_id=key_id,
                revoked_by=actor,
                revocation_run_id=f"github-actions-cleanup:{run_id}",
            )
            if not revoked:
                raise ApiKeyError("Active staging key could not be revoked")
            print(f"cleanup_revoked_key_id={key_id}")
        elif status == "revoked":
            print(f"staging_key_already_revoked={key_id}")
        else:
            raise ApiKeyError(
                f"Unexpected staging key state for cleanup: {status}"
            )

        integrity = PostgresSecurityEventStore(dsn).verify_integrity()
        if integrity.get("valid") is not True:
            raise ApiKeyError("Audit chain failed verification after cleanup")
        print("cleanup_audit_chain_valid=true")
        return 0
    except Exception as exc:
        # Only exception class and SQLSTATE are safe to log; never print the
        # exception message, DSN, host, or other connection details.
        print(f"cleanup_error_type={type(exc).__name__}", flush=True)
        direct_sqlstate = (
            getattr(exc, "sqlstate", None)
            or getattr(getattr(exc, "diag", None), "sqlstate", None)
            or getattr(exc, "pgcode", None)
        )
        print(f"cleanup_exception_module={type(exc).__module__}", flush=True)
        if direct_sqlstate:
            print(f"cleanup_sqlstate={direct_sqlstate}", flush=True)
        direct_constraint = getattr(getattr(exc, "diag", None), "constraint_name", None)
        if direct_constraint:
            print(f"cleanup_constraint={direct_constraint}")
        cause = exc.__cause__
        depth = 0
        while cause is not None and depth < 4:
            sqlstate = getattr(cause, "sqlstate", None)
            print(
                f"cleanup_cause_{depth + 1}_type={type(cause).__name__}"
                + (f" sqlstate={sqlstate}" if sqlstate else "")
            )
            cause = cause.__cause__
            depth += 1
        print("Staging key cleanup or audit verification failed.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
