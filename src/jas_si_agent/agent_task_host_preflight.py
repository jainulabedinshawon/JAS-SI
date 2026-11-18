"""Read-only database and capability preflight for agent host processes.

This proves connectivity and the exact database grants required by a host.
It does not claim that the API is ready or that a task was executed.
"""
from __future__ import annotations

from collections.abc import Sequence


class AgentHostPreflightError(RuntimeError):
    """Raised when a dedicated agent host database identity is not ready."""


def verify_agent_host_database_access(
    dsn: str,
    *,
    capability_role: str,
    required_functions: Sequence[str],
) -> None:
    """Verify DB connectivity, capability-role membership, and routine EXECUTE grants.

    Only fixed, caller-supplied routine signatures are accepted as query values;
    no SQL identifiers are interpolated. The query is read-only.
    """
    if not isinstance(dsn, str) or not dsn.strip():
        raise AgentHostPreflightError("Agent host database DSN is required")
    if capability_role not in {"jas_si_agent_worker", "jas_si_agent_verifier"}:
        raise AgentHostPreflightError("Agent host capability role is invalid")
    if not required_functions or any(
        not isinstance(item, str)
        or not item.startswith("public.jas_si_agent_task_")
        or "(" not in item
        for item in required_functions
    ):
        raise AgentHostPreflightError("Agent host routine allowlist is invalid")

    import psycopg

    privilege_checks = ", ".join(
        "pg_catalog.has_function_privilege(session_user, %s, 'EXECUTE')"
        for _ in required_functions
    )
    query = (
        "SELECT session_user, "
        "pg_catalog.pg_has_role(session_user, %s, 'MEMBER'), "
        f"{privilege_checks}"
    )
    parameters = (capability_role, *required_functions)

    try:
        with psycopg.connect(dsn, connect_timeout=5) as connection:
            with connection.cursor() as cursor:
                cursor.execute(query, parameters)
                row = cursor.fetchone()
    except Exception:
        # Driver errors can contain hostnames, usernames, or credential material.
        raise AgentHostPreflightError(
            "Agent host database connectivity or privilege preflight failed"
        ) from None

    if not row or len(row) != 2 + len(required_functions):
        raise AgentHostPreflightError("Agent host database preflight returned an invalid result")
    if row[1] is not True or any(value is not True for value in row[2:]):
        raise AgentHostPreflightError(
            "Agent host database identity lacks required capability-role or routine privileges"
        )


__all__ = ["AgentHostPreflightError", "verify_agent_host_database_access"]
