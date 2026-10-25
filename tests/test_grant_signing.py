
from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.authorization import AuthorizationGrant  # noqa: E402
from jas_si_agent.grant_signing import (  # noqa: E402
    GrantSigningError,
    sign_grant,
    verify_grant_signature,
)


class TestGrantSigning(unittest.TestCase):
    def setUp(self) -> None:
        self.key = b"test-only-secret-key-material-32bytes!"
        self.grant = AuthorizationGrant(
            grant_id="grant-001",
            approved_by="human-reviewer",
            human_approved=True,
            allowed_actions=("write_file",),
            allowed_resources=("docs/README.md",),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

    def test_valid_signature_verifies(self) -> None:
        signature = sign_grant(self.grant, self.key)
        self.assertTrue(
            verify_grant_signature(self.grant, signature, self.key)
        )

    def test_payload_mutation_invalidates_signature(self) -> None:
        signature = sign_grant(self.grant, self.key)
        altered = replace(
            self.grant,
            allowed_resources=("src/authorization.py",),
        )
        self.assertFalse(
            verify_grant_signature(altered, signature, self.key)
        )

    def test_approver_mutation_invalidates_signature(self) -> None:
        signature = sign_grant(self.grant, self.key)
        altered = replace(self.grant, approved_by="different-person")
        self.assertFalse(
            verify_grant_signature(altered, signature, self.key)
        )

    def test_wrong_key_is_rejected(self) -> None:
        signature = sign_grant(self.grant, self.key)
        self.assertFalse(
            verify_grant_signature(
                self.grant,
                signature,
                b"a-different-secret-key-with-32-bytes",
            )
        )

    def test_malformed_signature_is_rejected(self) -> None:
        self.assertFalse(
            verify_grant_signature(self.grant, "not-a-signature", self.key)
        )

    def test_short_key_is_rejected_when_signing(self) -> None:
        with self.assertRaises(GrantSigningError):
            sign_grant(self.grant, b"too-short")

    def test_short_key_is_rejected_when_verifying(self) -> None:
        self.assertFalse(
            verify_grant_signature(self.grant, "0" * 64, b"short")
        )

    def test_naive_expiry_is_rejected(self) -> None:
        grant = replace(
            self.grant,
            expires_at=datetime(2030, 1, 1, 12, 0, 0),
        )
        with self.assertRaises(GrantSigningError):
            sign_grant(grant, self.key)

    def test_action_scope_mutation_invalidates_signature(self) -> None:
        signature = sign_grant(self.grant, self.key)
        altered = replace(
            self.grant,
            allowed_actions=("create_pull_request",),
        )
        self.assertFalse(
            verify_grant_signature(altered, signature, self.key)
        )


if __name__ == "__main__":
    unittest.main()
