"""Read-only database and capability preflight for agent host processes."""
from __future__ import annotations

from collections.abc import Sequence


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
    expected_logins = {
        "jas_si_agent_worker": "jas_si_agent_worker_login",
        "jas_si_agent_verifier": "jas_si_agent_verifier_login",
    }
    if not isinstance(dsn, str) or not dsn.strip():
        raise AgentHostPreflightError("Agent host database DSN is required")
    if capability_role not in expected_logins or expected_login != expected_logins[capability_role]:
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
    table_checks = [
        "pg_catalog.has_table_privilege(current_user, 'public.jas_si_agent_tasks', 'SELECT')",
        "pg_catalog.has_table_privilege(current_user, 'public.jas_si_agent_tasks', 'UPDATE')",
        "pg_catalog.has_table_privilege(current_user, 'public.jas_si_agent_tasks', 'TRUNCATE')",
    ]
    if capability_role == "jas_si_agent_worker":
        table_checks.extend([
            "pg_catalog.has_table_privilege(current_user, 'public.jas_si_agent_tasks', 'INSERT')",
            "pg_catalog.has_table_privilege(current_user, 'public.jas_si_agent_tasks', 'DELETE')",
        ])
    if capability_role == "jas_si_agent_verifier":
        table_checks.extend([
            "pg_catalog.has_table_privilege(current_user, 'public.jas_si_agent_tasks', 'TRUNCATE')",
            "pg_catalog.has_table_privilege(current_user, 'public.jas_si_agent_evidence_records', 'SELECT')",
            "pg_catalog.has_table_privilege(current_user, 'public.jas_si_agent_evidence_records', 'INSERT')",
            "pg_catalog.has_table_privilege(current_user, 'public.jas_si_agent_evidence_records', 'TRUNCATE')",
        ])
    query = (
        "SELECT session_user, current_user, "
        + routine_checks + ", " + ", ".join(table_checks)
    )
    try:
        with psycopg.connect(dsn, connect_timeout=5) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET ROLE " + capability_role)
                cursor.execute(query, tuple(required_functions))
                row = cursor.fetchone()
    except Exception:
        raise AgentHostPreflightError(
            "Agent host database connectivity or privilege preflight failed"
        ) from None

    expected_length = 2 + len(required_functions) + len(table_checks)
    if not row or len(row) != expected_length:
        raise AgentHostPreflightError("Agent host database preflight returned an invalid result")
    routine_values = row[2 : 2 + len(required_functions)]
    table_values = row[2 + len(required_functions) :]
    if (
        row[0] != expected_login
        or row[1] != capability_role
        or any(value is not True for value in routine_values)
        or any(value is not False for value in table_values)
    ):
        raise AgentHostPreflightError(
            "Agent host identity, routine privileges, or direct-table boundary is invalid"
        )


__all__ = ["AgentHostPreflightError", "verify_agent_host_database_access"]
