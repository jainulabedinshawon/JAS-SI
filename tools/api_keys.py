"""Operator-only tenant and API-key provisioning utility.

Run from a trusted administrative shell after applying database migrations.
Issued tokens are displayed once and must be captured in an approved secret
manager. Never run this command in CI logs or a shared terminal.

The API runtime credential and operator credential are intentionally separate:
- JAS_SI_DATABASE_URL: least-privilege runtime role (used by the API only)
- JAS_SI_PROVISIONER_DATABASE_URL: operator role (used by this CLI only)
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.api_key_registry import (  # noqa: E402
    ALLOWED_SCOPES,
    ApiKeyError,
    PostgresApiKeyRegistry,
)
from jas_si_agent.postgres_security_event_store import (  # noqa: E402
    PostgresSecurityEventStore,
)


def _provisioner_dsn() -> str:
    dsn = os.getenv("JAS_SI_PROVISIONER_DATABASE_URL")
    if not dsn:
        raise ApiKeyError(
            "Set JAS_SI_PROVISIONER_DATABASE_URL to the operator-only database role"
        )
    return dsn


def _registry() -> PostgresApiKeyRegistry:
    dsn = _provisioner_dsn()
    pepper = os.getenv("JAS_SI_API_KEY_PEPPER")
    if not pepper or len(pepper.encode("utf-8")) < 32:
        raise ApiKeyError("Set JAS_SI_API_KEY_PEPPER (at least 32 bytes)")
    return PostgresApiKeyRegistry(dsn, pepper.encode("utf-8"))


def _audit(event: dict) -> None:
    PostgresSecurityEventStore(_provisioner_dsn()).append(event)


def main() -> int:
    parser = argparse.ArgumentParser(description="JAS-SI API key operator tool")
    sub = parser.add_subparsers(dest="command", required=True)

    tenant = sub.add_parser("create-tenant")
    tenant.add_argument("--name", required=True)
    tenant.add_argument("--created-by", required=True)

    issue = sub.add_parser("issue-key")
    issue.add_argument("--tenant-id", required=True)
    issue.add_argument("--name", required=True)
    issue.add_argument("--created-by", required=True)
    issue.add_argument(
        "--scope",
        action="append",
        required=True,
        choices=sorted(ALLOWED_SCOPES),
    )
    issue.add_argument("--expires-in-days", type=int, default=30)

    revoke = sub.add_parser("revoke-key")
    revoke.add_argument("--key-id", required=True)
    revoke.add_argument("--revoked-by", required=True)

    args = parser.parse_args()
    try:
        registry = _registry()
        if args.command == "create-tenant":
            tenant_id = registry.create_tenant(args.name)
            try:
                _audit({
                    "event_type": "tenant_created",
                    "tenant_id": str(tenant_id),
                    "tenant_name": args.name,
                    "operator_id": args.created_by,
                })
            except Exception:
                raise ApiKeyError(
                    "Tenant audit persistence failed; contact an administrator"
                ) from None
            print(f"tenant_id={tenant_id}")
            return 0

        if args.command == "issue-key":
            if args.expires_in_days < 1 or args.expires_in_days > 365:
                raise ApiKeyError("--expires-in-days must be between 1 and 365")
            tenant_id = UUID(args.tenant_id)
            audit_store = PostgresSecurityEventStore(_provisioner_dsn())
            integrity = audit_store.verify_integrity()
            if not integrity.get("valid"):
                raise ApiKeyError(
                    "Audit chain integrity check failed; provisioning stopped"
                )
            issued = registry.issue_key_with_audit(
                tenant_id=tenant_id,
                key_name=args.name,
                scopes=args.scope,
                created_by=args.created_by,
                provisioning_run_id=f"operator-cli:{uuid.uuid4()}",
                expires_at=datetime.now(timezone.utc)
                + timedelta(days=args.expires_in_days),
            )
            print("IMPORTANT: this token is displayed once. Store it securely.")
            print(f"key_id={issued.key_id}")
            print(f"expires_at={issued.expires_at.isoformat()}")
            print(f"api_key={issued.token}")
            return 0

        if args.command == "revoke-key":
            key_id = UUID(args.key_id)
            revoked = registry.revoke_key(key_id)
            if not revoked:
                raise ApiKeyError("Active API key was not found")
            _audit({
                "event_type": "api_key_revoked",
                "key_id": str(key_id),
                "operator_id": args.revoked_by,
            })
            print(f"revoked_key_id={key_id}")
            return 0

    except (ApiKeyError, ValueError) as exc:
        parser.error(str(exc))
    except Exception:
        parser.error(
            "Database operation failed; inspect secure server-side diagnostics."
        )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
