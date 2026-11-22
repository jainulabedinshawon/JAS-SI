"""PostgreSQL adapter for durable GitHub App webhook receipt.

The adapter persists authenticated delivery metadata only. It does not infer
tenant ownership, activate installations, or process lifecycle state.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class GitHubWebhookInboxError(RuntimeError):
    """A verified webhook could not be durably recorded."""


@dataclass(frozen=True)
class GitHubWebhookReceipt:
    delivery_id: str
    status: str
    attempt_count: int
    inserted: bool


class PostgresGitHubWebhookInbox:
    """Persist authenticated GitHub deliveries through the DB-owned routine.

    The DSN must identify the dedicated webhook login. It receives direct
    EXECUTE only on the receipt routine; it must not SET ROLE to the broader
    runtime capability. It must not be a superuser, migration owner, Worker,
    or Verifier connection.
    """

    def __init__(self, database_dsn: str) -> None:
        if not isinstance(database_dsn, str) or not database_dsn.strip():
            raise ValueError("A dedicated webhook database DSN is required")
        self._database_dsn = database_dsn

    def receive(
        self,
        *,
        delivery_id: str,
        event_name: str,
        action: str,
        installation_id: int,
        raw_body_sha256: bytes,
        payload: Mapping[str, Any],
    ) -> GitHubWebhookReceipt:
        if not isinstance(payload, Mapping):
            raise ValueError("Webhook payload must be an object")
        try:
            import psycopg
            from psycopg.types.json import Jsonb

            with psycopg.connect(self._database_dsn, connect_timeout=5) as connection:
                with connection.cursor() as cursor:
                    # Fail closed if an operator accidentally supplies a broad
                    # runtime, worker, verifier, or owner DSN.
                    cursor.execute("SELECT session_user")
                    identity = cursor.fetchone()
                    if not identity or identity[0] != "jas_si_github_webhook_login":
                        raise GitHubWebhookInboxError(
                            "Dedicated GitHub webhook database identity is required"
                        )
                    # The dedicated webhook login has direct EXECUTE on this
                    # SECURITY DEFINER routine. Do not SET ROLE: its runtime
                    # membership is deliberately non-inheriting and non-settable.
                    cursor.execute(
                        """SELECT delivery_id,status,attempt_count,inserted
                             FROM public.jas_si_github_webhook_receive(
                               %s,%s,%s,%s,%s,%s
                             )""",
                        (
                            delivery_id,
                            event_name,
                            action,
                            installation_id,
                            raw_body_sha256,
                            Jsonb(dict(payload)),
                        ),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise GitHubWebhookInboxError(
                            "Webhook receipt routine returned no result"
                        )
                    return GitHubWebhookReceipt(
                        delivery_id=row[0],
                        status=row[1],
                        attempt_count=row[2],
                        inserted=row[3],
                    )
        except GitHubWebhookInboxError:
            raise
        except Exception:
            # Never propagate database details, credentials, or payload values.
            raise GitHubWebhookInboxError(
                "GitHub webhook receipt could not be persisted"
            ) from None
