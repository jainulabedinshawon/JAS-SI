"""Restricted webhook-driven GitHub App Installation reconciliation worker.

The worker treats inbox rows only as wake-up signals. It fetches the live
Installation and complete repository set from GitHub's App API, then asks a
database-owned routine to reconcile only an existing pending ownership claim.
No webhook payload field is used as tenant, account, App, or repository truth.
"""
from __future__ import annotations

import base64
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

from jas_si_agent.github_app_api import (
    GitHubAppAPIError,
    GitHubAppInstallationAPI,
)

_LOG = logging.getLogger("jas_si.github_installation_reconciler")


@dataclass(frozen=True)
class GitHubReconcilerSettings:
    """Credentials loaded only by the isolated Render reconciler process."""

    app_id: int
    private_key_pem: bytes = field(repr=False)
    database_url: str = field(repr=False)
    poll_seconds: int = 15

    @classmethod
    def from_env(cls) -> "GitHubReconcilerSettings":
        raw_app_id = os.getenv("JAS_SI_GITHUB_APP_ID", "")
        if not raw_app_id.isdigit() or int(raw_app_id) <= 0:
            raise ValueError("JAS_SI_GITHUB_APP_ID must be a positive integer")
        raw_key = os.getenv("JAS_SI_GITHUB_APP_PRIVATE_KEY_B64", "")
        if not raw_key or len(raw_key) > 24000:
            raise ValueError("GitHub App private key is missing or too large")
        try:
            private_key = base64.b64decode(raw_key, validate=True)
        except Exception:
            raise ValueError("GitHub App private key must be valid base64") from None
        if not private_key.startswith(b"-----BEGIN ") or b"PRIVATE KEY-----" not in private_key[:80]:
            raise ValueError("GitHub App private key must encode a PEM private key")
        database_url = os.getenv("JAS_SI_GITHUB_RECONCILER_DATABASE_URL", "")
        if not database_url.strip():
            raise ValueError("Dedicated GitHub reconciler database URL is required")
        raw_poll = os.getenv("JAS_SI_GITHUB_RECONCILER_POLL_SECONDS", "15")
        if not raw_poll.isdigit() or not 1 <= int(raw_poll) <= 300:
            raise ValueError("JAS_SI_GITHUB_RECONCILER_POLL_SECONDS must be between 1 and 300")
        return cls(int(raw_app_id), private_key, database_url.strip(), int(raw_poll))


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
                cur.execute("SELECT session_user")
                identity = cur.fetchone()
                if not identity or identity[0] != "jas_si_github_reconciler_login":
                    raise RuntimeError("Dedicated GitHub reconciler database identity is required")
                cur.execute("SET ROLE jas_si_github_reconciler")
                cur.execute("SELECT current_user")
                capability = cur.fetchone()
                if not capability or capability[0] != "jas_si_github_reconciler":
                    raise RuntimeError("GitHub reconciler capability role was not assumed")
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

    def claim_pending(self, *, limit: int = 10) -> tuple[tuple[int, int], ...]:
        """Claim due pending OAuth claims even when their webhook arrived earlier."""
        try:
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """SELECT installation_id,attempt_count
                         FROM public.jas_si_github_installation_claim_pending(%s)""",
                    (limit,),
                )
                return tuple((int(row[0]), int(row[1])) for row in cur.fetchall())
        except Exception:
            raise RuntimeError("Pending GitHub Installation claims are unavailable") from None

    def process_pending_claims(self, *, limit: int = 10) -> dict[str, int]:
        claimed = self.claim_pending(limit=limit)
        counts = {"claimed": len(claimed), "reconciled": 0, "retry": 0}
        for installation_id, _attempt_count in claimed:
            try:
                snapshot = self._github.snapshot(installation_id=installation_id)
                state = self.apply_snapshot(
                    installation_id=installation_id, snapshot=snapshot
                )
                if state[0] in {"active", "suspended", "revoked"}:
                    counts["reconciled"] += 1
                else:
                    counts["retry"] += 1
            except Exception:
                # claim_pending() has already advanced a bounded retry time.
                # Do not log provider responses, private key details, or DSNs.
                counts["retry"] += 1
        return counts

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
                if state[0] not in {"active", "suspended", "revoked", "needs_review"}:
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


def build_reconciler(settings: GitHubReconcilerSettings) -> PostgresGitHubInstallationReconciler:
    github_api = GitHubAppInstallationAPI(
        app_id=settings.app_id,
        private_key_pem=settings.private_key_pem,
    )
    return PostgresGitHubInstallationReconciler(
        database_dsn=settings.database_url,
        github_api=github_api,
    )


def main() -> None:
    settings = GitHubReconcilerSettings.from_env()
    reconciler = build_reconciler(settings)
    poll_seconds = settings.poll_seconds
    _LOG.info("GitHub Installation reconciler started; poll_seconds=%s", poll_seconds)
    while True:
        try:
            webhook_counts = reconciler.process_batch(limit=10)
            pending_counts = reconciler.process_pending_claims(limit=10)
            if webhook_counts["claimed"] or pending_counts["claimed"]:
                _LOG.info(
                    "GitHub reconciliation: webhook_claimed=%s webhook_processed=%s "
                    "webhook_retry=%s lease_lost=%s pending_claimed=%s pending_reconciled=%s "
                    "pending_retry=%s",
                    webhook_counts["claimed"], webhook_counts["processed"],
                    webhook_counts["retry"], webhook_counts["lease_lost"],
                    pending_counts["claimed"], pending_counts["reconciled"],
                    pending_counts["retry"],
                )
        except Exception:
            _LOG.error("GitHub Installation reconciliation cycle failed")
        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
