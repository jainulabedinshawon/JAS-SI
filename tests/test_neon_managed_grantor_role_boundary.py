"""Exercise the Worker/Verifier login boundary with a Neon-like grantor graph.

This runs only against the disposable PostgreSQL service used by migration CI.
It never connects to Neon or any shared environment.
"""
from __future__ import annotations

import os
from pathlib import Path

import psycopg


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    dsn = os.environ["JAS_SI_MIGRATION_REPLAY_DATABASE_URL"]
    migration = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "jas_si_agent"
        / "migrations"
        / "20261214_agent_login_set_role_boundary.sql"
    ).read_text(encoding="utf-8")

    pairs = (
        ("jas_si_agent_worker_login", "jas_si_agent_worker"),
        ("jas_si_agent_verifier_login", "jas_si_agent_verifier"),
    )

    # The disposable migration replay DB is bootstrapped by its superuser.
    # Rebuild the relevant membership graph from scratch so the test is
    # deterministic and models the live Neon grantor/options topology.
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            for login, capability in pairs:
                cur.execute(
                    "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s), "
                    "EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s)",
                    (login, capability),
                )
                login_exists, capability_exists = cur.fetchone()
                require(login_exists, f"Required login role missing: {login}")
                require(capability_exists, f"Required capability role missing: {capability}")

                cur.execute(f'ALTER ROLE "{login}" INHERIT')
                cur.execute(f'REVOKE "{capability}" FROM "{login}"')
                cur.execute(f'REVOKE "{capability}" FROM neondb_owner')
                cur.execute(f'REVOKE "{capability}" FROM cloud_admin')
                cur.execute(f'REVOKE "{login}" FROM neondb_owner')
                cur.execute(f'REVOKE "{login}" FROM cloud_admin')
                cur.execute(
                    f'GRANT "{capability}" TO cloud_admin '
                    "WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"
                )
                cur.execute(
                    f'GRANT "{login}" TO cloud_admin '
                    "WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"
                )

            # cloud_admin is the upstream managed grantor and delegates
            # ADMIN OPTION to neondb_owner, matching the Neon graph.
            cur.execute("SET SESSION AUTHORIZATION cloud_admin")
            for login, capability in pairs:
                cur.execute(
                    f'GRANT "{capability}" TO neondb_owner '
                    "WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"
                )
                cur.execute(
                    f'GRANT "{login}" TO neondb_owner '
                    "WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"
                )
            cur.execute("RESET SESSION AUTHORIZATION")

            # neondb_owner is the direct grantor of the two service logins.
            cur.execute("SET SESSION AUTHORIZATION neondb_owner")
            for login, capability in pairs:
                cur.execute(
                    f'GRANT "{capability}" TO "{login}" '
                    "WITH ADMIN FALSE, INHERIT TRUE, SET TRUE"
                )
            cur.execute("RESET SESSION AUTHORIZATION")

            # Run the actual migration under the same database principal that
            # owns the direct grants, not under the CI bootstrap superuser.
            cur.execute("SET SESSION AUTHORIZATION neondb_owner")
            cur.execute(migration, prepare=False)
            cur.execute("RESET SESSION AUTHORIZATION")

            for login, capability in pairs:
                cur.execute(
                    """
                    SELECT role.rolinherit,
                           membership.inherit_option,
                           membership.set_option,
                           membership.admin_option,
                           membership.grantor::regrole::text
                      FROM pg_catalog.pg_roles role
                      JOIN pg_catalog.pg_auth_members membership
                        ON membership.member=role.oid
                      JOIN pg_catalog.pg_roles granted
                        ON granted.oid=membership.roleid
                     WHERE role.rolname=%s AND granted.rolname=%s
                    """,
                    (login, capability),
                )
                row = cur.fetchone()
                require(row is not None, f"Migration removed expected membership: {login}")
                rolinherit, inherit_option, set_option, admin_option, grantor = row
                require(rolinherit is False, f"{login} still has INHERIT enabled")
                require(inherit_option is False, f"{login} membership still inherits")
                require(set_option is True, f"{login} membership cannot SET ROLE")
                require(admin_option is False, f"{login} unexpectedly has ADMIN OPTION")
                require(grantor == "neondb_owner", f"{login} grantor changed unexpectedly: {grantor}")

    print(
        "PASS: Neon-like cloud_admin -> neondb_owner -> Worker/Verifier "
        "grantor graph; migration executed as neondb_owner; both logins "
        "verified NOINHERIT / SET-only / non-admin."
    )


if __name__ == "__main__":
    main()
