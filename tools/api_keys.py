"""Operator-only tenant and API-key provisioning utility.

Run from a trusted administrative shell after applying database migrations.
The issued token is printed once to stdout; capture it in an approved secret
manager/channel. Never run this command in CI logs or a shared terminal.
"""

from __future__ import annotations

import argparse
import os
import sys
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


def _registry() -> PostgresApiKeyRegistry:
    dsn = os.getenv("JAS_SI_DATABASE_URL")
    pepper = os.getenv("JAS_SI_API_KEY_PEPPER")
    if not dsn:
        raise ApiKeyError("Set JAS_SI_DATABASE_URL")
    if not pepper or len(pepper.encode("utf-8")) < 32:
        raise ApiKeyError("Set JAS_SI_API_KEY_PEPPER (at least 32 bytes)")
    return PostgresApiKeyRegistry(dsn, pepper.encode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="JAS-SI API key operator tool")
    sub = parser.add_subparsers(dest="command", required=True)

    tenant = sub.add_parser("create-tenant")
    tenant.add_argument("--name", required=True)\n    tenant.add_argument("--created-by", required=True)

    issue = sub.add_parser("issue-key")
    issue.add_argument("--tenant-id", required=True)
    issue.add_argument("--name", required=True)
    issue.add_argument("--created-by", required=True)
    issue.add_argument("--scope", action="append", required=True, choices=sorted(ALLOWED_SCOPES))
    issue.add_argument("--expires-in-days", type=int, default=30)

    revoke = sub.add_parser("revoke-key")
    revoke.add_argument("--key-id", required=True)\n    revoke.add_argument("--revoked-by", required=True)

    args = parser.parse_args()
    try:
        registry = _registry()
        if args.command == "create-tenant":
            tenant_id = registry.create_tenant(args.name)
            print(f"tenant_id={tenant_id}")
            return 0

        if args.command == "issue-key":
            if args.expires_in_days < 1 or args.expires_in_days > 365:
                raise ApiKeyError("--expires-in-days must be between 1 and 365")
            issued = registry.issue_key(
                tenant_id=UUID(args.tenant_id),
                key_name=args.name,
                scopes=args.scope,
                created_by=args.created_by,
                expires_at=datetime.now(timezone.utc) + timedelta(days=args.expires_in_days),
            )
            try:\n                PostgresSecurityEventStore(os.environ["JAS_SI_DATABASE_URL"]).append({\n                    "event_type": "api_key_issued",\n                    "tenant_id": str(tenant_id),\n                    "key_id": str(issued.key_id),\n                    "key_name": args.name,\n                    "scopes": sorted(set(args.scope)),\n                    "expires_at": issued.expires_at.isoformat(),\n                    "operator_id": args.created_by,\n                })\n            except Exception:\n                registry.revoke_key(issued.key_id)\n                raise ApiKeyError("Key audit persistence failed; issued key was revoked") from None\n            print("IMPORTANT: this token is displayed once. Store it securely.")
            print(f"key_id={issued.key_id}")
            print(f"expires_at={issued.expires_at.isoformat()}")
            print(f"api_key={issued.token}")
            return 0

        if args.command == "revoke-key":
            revoked = registry.revoke_key(UUID(args.key_id))
            if not revoked:
                raise ApiKeyError("Active API key was not found")
            PostgresSecurityEventStore(os.environ["JAS_SI_DATABASE_URL"]).append({\n                "event_type": "api_key_revoked",\n                "key_id": str(args.key_id),\n                "operator_id": args.revoked_by,\n            })\n            print(f"revoked_key_id={args.key_id}")
            return 0

    except (ApiKeyError, ValueError) as exc:
        parser.error(str(exc))
    except Exception:
        parser.error("Database operation failed; inspect secure server-side diagnostics.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
