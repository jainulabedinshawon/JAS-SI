"""Read-only database and capability preflight for agent host processes."""
from __future__ import annotations

from collections.abc import Sequence
import re


class AgentHostPreflightError(RuntimeError):
    """Raised when a dedicated agent host database identity is not ready."""


def verify_agent_host_database_access(
    dsn: str,
    *,
    capability_role: str,
    expected_login: str,
    required_functions: Sequence[str],
) -> None:
    """Verify dedicated login, capability switch, routine grants, and table isolation."""
    expected_login_patterns = {
        "jas_si_agent_worker": r"jas_si_agent_worker_login(?:_[a-z0-9_]{1,32})?",
        "jas_si_agent_verifier": r"jas_si_agent_verifier_login(?:_[a-z0-9_]{1,32})?",
    }
    forbidden_roles = (
        "jas_si_agent_task_owner",
        "jas_si_github_reconciler",
        "jas_si_runtime",
        "jas_si_provisioner",
        "neondb_owner",
    )
    if not isinstance(dsn, str) or not dsn.strip():
        raise AgentHostPreflightError("Agent host database DSN is required")
    if (
        capability_role not in expected_login_patterns
        or not isinstance(expected_login, str)
        or re.fullmatch(expected_login_patterns[capability_role], expected_login) is None
    ):
        raise AgentHostPreflightError("Agent host database identity is invalid")
    if not required_functions or any(
        not isinstance(item, str)
        or not item.startswith("public.jas_si_agent_task_")
        or "(" not in item
        or not item.endswith(")")
        for item in required_functions
    ):
        raise AgentHostPreflightError("Agent host routine allowlist is invalid")

    import psycopg

    routine_checks = ", ".join(
        "pg_catalog.has_function_privilege(current_user, %s, 'EXECUTE')"
        for _ in required_functions
    )
    # Neither host may read or mutate task/evidence tables directly. All
    # access must pass through the narrowly granted SECURITY DEFINER routines.
    table_checks = []
    for table in (
        "public.jas_si_agent_tasks",
        "public.jas_si_agent_evidence_records",
    ):
        for privilege in (
            "SELECT", "INSERT", "UPDATE", "DELETE",
            "TRUNCATE", "REFERENCES", "TRIGGER",
        ):
            table_checks.append(
                "pg_catalog.has_table_privilege(current_user, "
                + repr(table) + ", " + repr(privilege) + ")"
            )
        for privilege in ("SELECT", "INSERT", "UPDATE", "REFERENCES"):
            table_checks.append(
                "pg_catalog.has_any_column_privilege(current_user, "
                + repr(table) + ", " + repr(privilege) + ")"
            )
    forbidden_role = (
        "jas_si_agent_verifier"
        if capability_role == "jas_si_agent_worker"
        else "jas_si_agent_worker"
    )
    query = (
        "SELECT session_user, current_user, "
        "pg_catalog.pg_has_role(session_user, %s, 'MEMBER'), "
        "EXISTS (SELECT 1 FROM pg_catalog.pg_roles login_role "
        "WHERE login_role.rolname=session_user "
        "AND (NOT login_role.rolcanlogin OR login_role.rolsuper "
        "OR login_role.rolcreatedb OR login_role.rolcreaterole "
        "OR login_role.rolreplication OR login_role.rolbypassrls "
        "OR login_role.rolinherit)), "
        "EXISTS (SELECT 1 FROM pg_catalog.pg_roles privileged_role "
        "WHERE privileged_role.rolname = ANY(%s::text[]) "
        "AND pg_catalog.pg_has_role(session_user, privileged_role.oid, 'MEMBER')), "
        + routine_checks + ", " + ", ".join(table_checks)
    )
    try:
        with psycopg.connect(dsn, connect_timeout=5) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET ROLE " + capability_role)
                cursor.execute(query, (forbidden_role, list(forbidden_roles), *required_functions))
                row = cursor.fetchone()
    except Exception:
        raise AgentHostPreflightError(
            "Agent host database connectivity or privilege preflight failed"
        ) from None

    expected_length = 5 + len(required_functions) + len(table_checks)
    if not row or len(row) != expected_length:
        raise AgentHostPreflightError("Agent host database preflight returned an invalid result")
    forbidden_role_membership = row[2]
    unsafe_login_attributes = row[3]
    privileged_role_membership = row[4]
    routine_values = row[5 : 5 + len(required_functions)]
    table_values = row[5 + len(required_functions) :]
    if (
        row[0] != expected_login
        or row[1] != capability_role
        or forbidden_role_membership is not False
        or unsafe_login_attributes is not False
        or privileged_role_membership is not False
        or any(value is not True for value in routine_values)
        or any(value is not False for value in table_values)
    ):
        raise AgentHostPreflightError(
            "Agent host identity, role membership, routine privileges, or direct-table boundary is invalid"
        )


__all__ = ["AgentHostPreflightError", "verify_agent_host_database_access"]
