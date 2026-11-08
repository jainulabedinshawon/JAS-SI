"""Protected GitHub Actions API-key issuance with ciphertext-only delivery.

This utility is intended only for a manually approved GitHub Environment job.
It never prints or writes the raw API token. The token is encrypted to exactly
one operator-held OpenPGP public key before any delivery artifact is created.
"""

from __future__ import annotations

import argparse
import json
import os
import re
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
from jas_si_agent.secure_token_delivery import (  # noqa: E402
    TokenDeliveryError,
    encrypt_token_for_recipient,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Issue a JAS-SI staging key and deliver encrypted ciphertext only"
    )
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--key-name", required=True)
    parser.add_argument("--scope", required=True, choices=sorted(ALLOWED_SCOPES))
    parser.add_argument("--expires-in-days", required=True, type=int)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    issued = None
    registry = None
    operator = os.getenv("GITHUB_ACTOR", "github-actions")
    try:
        allowed_tenant = os.getenv("JAS_SI_ALLOWED_TENANT_ID", "")
        if not allowed_tenant or args.tenant_id != allowed_tenant:
            raise ApiKeyError("Tenant is not allowlisted for this workflow")
        tenant_id = UUID(args.tenant_id)
        if not re.fullmatch(r"[A-Za-z0-9._ -]{1,64}", args.key_name):
            raise ApiKeyError("Invalid key name")
        if not 1 <= args.expires_in_days <= 7:
            raise ApiKeyError("Staging key expiry must be between 1 and 7 days")
        if not re.fullmatch(r"github-actions:[0-9]{1,20}", args.run_id):
            raise ApiKeyError("Invalid workflow run identifier")

        dsn = os.getenv("JAS_SI_PROVISIONER_DATABASE_URL", "")
        pepper = os.getenv("JAS_SI_API_KEY_PEPPER", "")
        recipient = os.getenv("RECIPIENT_PUBLIC_KEY", "")
        if not dsn or len(pepper.encode("utf-8")) < 32:
            raise ApiKeyError("Provisioning secrets are not configured")
        if not recipient:
            raise TokenDeliveryError("Operator public key is required")

        output_dir = Path(args.output_dir)
        output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        registry = PostgresApiKeyRegistry(dsn, pepper.encode("utf-8"))
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=args.expires_in_days
        )

        issued = registry.issue_key_with_audit(
            tenant_id=tenant_id,
            key_name=args.key_name,
            scopes=[args.scope],
            created_by=operator,
            provisioning_run_id=args.run_id,
            expires_at=expires_at,
        )

        ciphertext = encrypt_token_for_recipient(issued.token, recipient)
        (output_dir / "api-key.asc").write_bytes(ciphertext)
        metadata = {
            "key_id": str(issued.key_id),
            "tenant_id": str(tenant_id),
            "key_name": args.key_name,
            "scope": args.scope,
            "expires_at": expires_at.isoformat(),
            "provisioning_run_id": args.run_id,
            "delivery": "openpgp-encrypted",
        }
        (output_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        github_output = os.getenv("GITHUB_OUTPUT")
        if not github_output:
            raise ApiKeyError("GitHub output channel is unavailable")
        with Path(github_output).open("a", encoding="utf-8") as output:
            output.write(f"key_id={issued.key_id}\n")

        print(f"issued_key_id={issued.key_id}")
        print("encrypted_delivery_artifact_ready=true")
        return 0

    except Exception:
        if issued is not None and registry is not None:
            try:
                registry.revoke_key_with_audit(
                    key_id=issued.key_id,
                    revoked_by=operator,
                    revocation_run_id=f"{args.run_id}:delivery-failure",
                )
                print(f"delivery_failed_key_revoked={issued.key_id}")
            except Exception:
                print(
                    "SECURITY ALERT: encrypted delivery failed and automatic "
                    f"revocation could not be confirmed; revoke key_id={issued.key_id}"
                )
        else:
            print("Provisioning stopped before a key was issued.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
