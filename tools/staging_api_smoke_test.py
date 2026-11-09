"""Issue, exercise, and revoke one short-lived staging API key in one process.

The raw token exists only in process memory and is sent only over HTTPS to the
fixed, trusted Preview deployment. It is never printed, persisted, exported to
GitHub outputs, or uploaded as an artifact.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.api_key_registry import (  # noqa: E402
    ApiKeyError,
    PostgresApiKeyRegistry,
)
from jas_si_agent.postgres_security_event_store import (  # noqa: E402
    PostgresSecurityEventStore,
)

TENANT_ID = UUID("277b9f5a-160a-44d6-b47f-706decdfda03")
# Immutable Vercel Preview deployment URL; do not accept this from workflow input.
API_BASE_URL = os.getenv("JAS_SI_PREVIEW_BASE_URL", "").rstrip("/")
if not API_BASE_URL.startswith("https://jas-") or not API_BASE_URL.endswith("-jainulabedinshan-3242.vercel.app"):
    raise RuntimeError("A trusted JAS-SI Preview deployment URL is required.")


def request_response(path: str, token: str | None) -> tuple[int, dict]:
    import json

    if path == "/v1/verify":
        # Supply a valid VerifyRequest so the response proves the authorized verification route remains
        # inconclusive when no independently collected evidence is supplied.
        body = {
            "action_id": "jas-si-staging-auth-smoke",
            "claimed_success": True,
        }
    else:
        body = {
            "action_id": "jas-si-staging-auth-smoke",
            "action": "read_staging_health",
            "resource": "jas-si://staging/authentication-smoke-test",
        }
    request = urllib.request.Request(
        API_BASE_URL + path,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            **({"X-API-Key": token} if token is not None else {}),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            raw = response.read(65536)
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read(65536)
        try:
            payload = json.loads(raw) if raw else {}
        except Exception:
            payload = {}
        return exc.code, payload


def main() -> int:
    dsn = os.getenv("JAS_SI_PROVISIONER_DATABASE_URL", "")
    pepper = os.getenv("JAS_SI_API_KEY_PEPPER", "")
    run_id = os.getenv("GITHUB_RUN_ID", "")
    actor = os.getenv("GITHUB_ACTOR", "github-actions")
    if not dsn or len(pepper.encode("utf-8")) < 32:
        print("Provisioning secrets are missing or invalid.")
        return 2
    if not run_id.isdigit():
        print("GitHub run identity is invalid.")
        return 2

    issued = None
    revoked = False
    checks: list[tuple[str, bool]] = []
    try:
        import psycopg

        with psycopg.connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT current_database(),
                           to_regclass('public.jas_si_tenants') IS NOT NULL,
                           to_regclass('public.jas_si_api_keys') IS NOT NULL,
                           to_regclass('public.jas_si_api_key_provisioning_runs') IS NOT NULL,
                           to_regclass('public.jas_si_audit_events') IS NOT NULL,
                           to_regclass('public.jas_si_audit_chain_state') IS NOT NULL
                    """
                )
                db_name, tenants_ok, keys_ok, runs_ok, audit_ok, chain_ok = cursor.fetchone()
                print(f"staging_database_name={db_name}")
                print(
                    "staging_schema_preflight="
                    f"{int(tenants_ok)}{int(keys_ok)}{int(runs_ok)}"
                    f"{int(audit_ok)}{int(chain_ok)}"
                )
                cursor.execute(
                    "SELECT tenant_name, status FROM public.jas_si_tenants WHERE tenant_id = %s",
                    (str(TENANT_ID),),
                )
                tenant = cursor.fetchone()
        if tenant != ("JAS-SI Internal Staging", "active"):
            raise RuntimeError("Configured staging tenant identity check failed")
        print("staging_tenant_identity=PASS")

        registry = PostgresApiKeyRegistry(dsn, pepper.encode("utf-8"))
        print("provisioner_constructor=PASS")
        issued = registry.issue_key_with_audit(
            tenant_id=TENANT_ID,
            key_name=f"ci-staging-smoke-{run_id}",
            scopes=["authorization:check", "outcomes:submit"],
            created_by=actor,
            provisioning_run_id=f"github-actions:{run_id}",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )

        # Mask the token before any later step can emit it.
        print(f"::add-mask::{issued.token}")

        # Authentication negative cases: missing and malformed/unknown key.
        checks.append(("missing_key_401", request_response("/v1/authorize", None)[0] == 401))
        checks.append((
            "invalid_key_401",
            request_response("/v1/authorize", "jassi_live_invalid_invalid")[0] == 401,
        ))
        # Positive authenticated requests use the real Preview API.
        checks.append((
            "valid_key_authorized_endpoint_200",
            request_response("/v1/authorize", issued.token)[0] == 200,
        ))
        verify_status, verify_body = request_response("/v1/verify", issued.token)
        checks.append((
            "valid_key_verify_inconclusive_without_independent_evidence",
            verify_status == 200 and verify_body.get("status") == "INCONCLUSIVE",
        ))
    except Exception as exc:
        # Report exception classes and database SQLSTATE only; never print
        # exception messages, which may contain connection or secret material.
        print(f"staging_error_type={type(exc).__name__}")
        direct_sqlstate = getattr(exc, "sqlstate", None)
        if direct_sqlstate:
            print(f"staging_sqlstate={direct_sqlstate}")
        direct_constraint = getattr(getattr(exc, "diag", None), "constraint_name", None)
        if direct_constraint:
            print(f"staging_constraint={direct_constraint}")
        cause = exc.__cause__
        depth = 0
        while cause is not None and depth < 4:
            sqlstate = getattr(cause, "sqlstate", None)
            print(
                f"staging_cause_{depth + 1}_type={type(cause).__name__}"
                + (f" sqlstate={sqlstate}" if sqlstate else "")
            )
            cause = cause.__cause__
            depth += 1
        print("Staging API smoke checks encountered an error.")
    finally:
        if issued is not None:
            try:
                revoked = registry.revoke_key_with_audit(
                    key_id=issued.key_id,
                    revoked_by=actor,
                    revocation_run_id=f"github-actions-revoke:{run_id}",
                )
            except Exception:
                print(
                    "CRITICAL: automatic key revocation failed; "
                    f"key_id={issued.key_id}; manual revocation is required."
                )

    if issued is None:
        print("No staging key was issued.")
        return 1
    if not revoked:
        print(f"CRITICAL: key revocation was not confirmed; key_id={issued.key_id}")
        return 1

    # Verify the revoked credential is rejected by the same independent API.
    try:
        checks.append((
            "revoked_key_rejected_401",
            request_response("/v1/authorize", issued.token)[0] == 401,
        ))
        integrity = PostgresSecurityEventStore(dsn).verify_integrity()
        checks.append(("audit_chain_valid_after_revoke", integrity.get("valid") is True))

        import psycopg

        with psycopg.connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT event_payload->>'event_type'
                    FROM jas_si_audit_events
                    WHERE event_payload->>'key_id' = %s
                      AND event_payload->>'event_type' IN (
                          'api_key_issued', 'api_key_revoked'
                      )
                    ORDER BY event_id
                    """,
                    (str(issued.key_id),),
                )
                event_types = [row[0] for row in cursor.fetchall()]
        checks.append((
            "exact_issue_and_revoke_audit_events",
            event_types == ["api_key_issued", "api_key_revoked"],
        ))
    except Exception:
        print("Independent post-revocation verification failed.")
        return 1

    for name, passed in checks:
        print(f"{name}={'PASS' if passed else 'FAIL'}")
    print(f"revoked_key_id={issued.key_id}")
    print(f"checks_passed={sum(p for _, p in checks)}/{len(checks)}")
    return 0 if all(passed for _, passed in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
