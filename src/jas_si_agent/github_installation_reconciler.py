"""Restricted webhook-driven GitHub App Installation reconciliation worker.

The worker treats inbox rows only as wake-up signals. It fetches the live
Installation and complete repository set from GitHub's App API, then asks a
database-owned routine to reconcile only an existing pending ownership claim.
No webhook payload field is used as tenant, account, App, or repository truth.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from jas_si_agent.github_app_api import (
    GitHubAppAPIError,
    GitHubAppInstallationAPI,
)
from jas_si_agent.config import Settings

_LOG = logging.getLogger("jas_si.github_installation_reconciler")


@dataclass(frozen=True)
class ClaimedWebhook:
    delivery_id: str
    event_name: str
    action: str
    installation_id: int
    attempt_count: int
    claim_token: Any


class PostgresGitHubInstallationReconciler:
    """Use execute-only PostgreSQL routines for inbox and binding changes."""

    def __init__(self, *, database_dsn: str, github_api: GitHubAppInstallationAPI) -> None:
        if not isinstance(database_dsn, str) or not database_dsn.strip():
            raise ValueError("Dedicated GitHub reconciler database DSN is required")
        self._dsn = database_dsn.strip()
        self._github = github_api

    def _connect(self):
        import psycopg
        conn = psycopg.connect(self._dsn, connect_timeout=5)
        try:
            with conn.cursor() as cur:
                cur.execute("SET ROLE jas_si_github_reconciler")
            return conn
        except Exception:
            conn.close()
            raise

    def claim(self, *, limit: int = 10, lease_seconds: int = 120) -> tuple[ClaimedWebhook, ...]:
        try:
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """SELECT delivery_id,event_name,action,installation_id,
                              attempt_count,claim_token
                         FROM public.jas_si_github_webhook_claim(%s,%s)""",
                    (limit, lease_seconds),
                )
                rows = cur.fetchall()
            return tuple(ClaimedWebhook(
                delivery_id=row[0],
                event_name=row[1],
                action=row[2],
                installation_id=int(row[3]),
                attempt_count=int(row[4]),
                claim_token=row[5],
            ) for row in rows)
        except Exception:
            raise RuntimeError("GitHub reconciliation inbox is unavailable") from None

    def apply_snapshot(self, *, installation_id: int, snapshot) -> tuple[str, str, int]:
        missing = snapshot is None
        repositories = [] if missing or snapshot.suspended else [
            {
                "id": item.repository_id,
                "full_name": item.full_name,
                "private": item.private,
            }
            for item in snapshot.repositories
        ]
        try:
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """SELECT claim_status,installation_status,repository_count
                         FROM public.jas_si_github_installation_reconcile_apply(
                           %s,%s,%s,%s,%s,%s,%s,%s::jsonb
                         )""",
                    (
                        installation_id,
                        None if missing else snapshot.app_id,
                        None if missing else snapshot.account_id,
                        None if missing else snapshot.account_login,
                        None if missing else snapshot.account_type,
                        False if missing else snapshot.suspended,
                        missing,
                        __import__("json").dumps(repositories),
                    ),
                )
                row = cur.fetchone()
                if row is None:
                    raise RuntimeError("Reconciliation routine returned no state")
                return str(row[0]), str(row[1]), int(row[2])
        except Exception:
            raise RuntimeError("GitHub Installation binding could not be reconciled") from None

    def mark_processed(self, *, delivery_id: str, claim_token) -> bool:
        try:
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT public.jas_si_github_webhook_mark_processed(%s,%s)",
                    (delivery_id, claim_token),
                )
                row = cur.fetchone()
                return bool(row and row[0])
        except Exception:
            raise RuntimeError("GitHub webhook completion could not be recorded") from None

    def mark_failed(
        self, *, delivery_id: str, error_code: str, claim_token,
        retry_delay_seconds: int = 60,
    ) -> bool:
        try:
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """SELECT public.jas_si_github_webhook_mark_failed(%s,%s,%s,%s)""",
                    (delivery_id, error_code, claim_token, retry_delay_seconds),
                )
                row = cur.fetchone()
                return bool(row and row[0])
        except Exception:
            raise RuntimeError("GitHub webhook retry state could not be recorded") from None

    def process_batch(self, *, limit: int = 10) -> dict[str, int]:
        claimed = self.claim(limit=limit)
        counts = {"claimed": len(claimed), "processed": 0, "retry": 0, "lease_lost": 0}
        for event in claimed:
            try:
                # The event payload is deliberately ignored. Its Installation
                # ID is only a candidate lookup key; GitHub App API is truth.
                snapshot = self._github.snapshot(installation_id=event.installation_id)
                state = self.apply_snapshot(
                    installation_id=event.installation_id, snapshot=snapshot
                )
                if state[0] == "NO_CLAIM":
                    if self.mark_failed(
                        delivery_id=event.delivery_id,
                        error_code="CLAIM_NOT_FOUND",
                        claim_token=event.claim_token,
                        retry_delay_seconds=60,
                    ):
                        counts["retry"] += 1
                    else:
                        counts["lease_lost"] += 1
                    continue
                if state[0] not in {"active", "suspended", "revoked"}:
                    raise RuntimeError("Unexpected Installation reconciliation state")
                if self.mark_processed(
                    delivery_id=event.delivery_id, claim_token=event.claim_token
                ):
                    counts["processed"] += 1
                else:
                    counts["lease_lost"] += 1
            except GitHubAppAPIError:
                if self.mark_failed(
                    delivery_id=event.delivery_id,
                    error_code="GITHUB_API_UNAVAILABLE",
                    claim_token=event.claim_token,
                    retry_delay_seconds=60,
                ):
                    counts["retry"] += 1
                else:
                    counts["lease_lost"] += 1
            except Exception:
                # Error messages and provider payloads are never logged.
                try:
                    failed = self.mark_failed(
                        delivery_id=event.delivery_id,
                        error_code="RECONCILIATION_FAILED",
                        claim_token=event.claim_token,
                        retry_delay_seconds=60,
                    )
                except Exception:
                    failed = False
                if failed:
                    counts["retry"] += 1
                else:
                    counts["lease_lost"] += 1
        return counts


def build_reconciler(settings: Settings) -> PostgresGitHubInstallationReconciler:
    if not settings.github_app_id or not settings.github_app_private_key_pem:
        raise RuntimeError("GitHub App ID and private key are required by the reconciler")
    if not settings.github_reconciler_database_url:
        raise RuntimeError("Dedicated GitHub reconciler database URL is required")
    github_api = GitHubAppInstallationAPI(
        app_id=settings.github_app_id,
        private_key_pem=settings.github_app_private_key_pem,
    )
    return PostgresGitHubInstallationReconciler(
        database_dsn=settings.github_reconciler_database_url,
        github_api=github_api,
    )


def main() -> None:
    settings = Settings.from_env()
    reconciler = build_reconciler(settings)
    poll_seconds = settings.github_reconciler_poll_seconds
    _LOG.info("GitHub Installation reconciler started; poll_seconds=%s", poll_seconds)
    while True:
        try:
            counts = reconciler.process_batch(limit=10)
            if counts["claimed"]:
                _LOG.info(
                    "GitHub reconciliation batch: claimed=%s processed=%s retry=%s lease_lost=%s",
                    counts["claimed"], counts["processed"], counts["retry"], counts["lease_lost"],
                )
        except Exception:
            _LOG.error("GitHub Installation reconciliation cycle failed")
        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
