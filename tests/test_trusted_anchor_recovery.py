from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_hmac import create_signed_receipt
from jas_si_agent.trusted_anchor_provider import TrustedAnchorReceipt
from jas_si_agent.trusted_anchor_recovery import (
    TrustedAnchorRecoveryError,
    recover_or_publish_anchor,
)


SECRET = b"jas-si-recovery-test-secret-at-least-32-bytes"


class FakeRecoverableProvider:
    """Test double only; not a real external provider."""

    def __init__(self, verification_result: bool = True) -> None:
        self.verification_result = verification_result
        self.records: dict[str, TrustedAnchorReceipt] = {}
        self.lookup_calls = 0
        self.publish_calls = 0

    def lookup_by_idempotency_key(
        self,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt | None:
        self.lookup_calls += 1
        return self.records.get(idempotency_key)

    def publish_idempotent(
        self,
        anchor: SecurityCheckpointAnchor,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt:
        self.publish_calls += 1

        existing = self.records.get(idempotency_key)
        if existing is not None:
            if existing.anchor_digest != anchor.digest:
                raise ValueError("Idempotency key conflict")
            return existing

        receipt = create_signed_receipt(
            provider_id="test-recovery-provider",
            anchor_digest=anchor.digest,
            external_reference=f"recovery-{idempotency_key[:12]}",
            observed_at="2026-10-30T00:00:00Z",
            secret=SECRET,
        )

        self.records[idempotency_key] = receipt
        return receipt

    def verify(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ) -> bool:
        return (
            self.verification_result
            and receipt.anchor_digest == anchor.digest
        )


class TestTrustedAnchorRecovery(unittest.TestCase):

    def setUp(self) -> None:
        self.anchor = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=6,
            last_hash="c" * 64,
        )

    def test_existing_publication_is_recovered_without_republishing(
        self,
    ) -> None:
        provider = FakeRecoverableProvider()

        original = provider.publish_idempotent(
            self.anchor,
            self.anchor.digest,
        )

        receipt = recover_or_publish_anchor(
            provider,
            self.anchor,
        )

        self.assertEqual(receipt, original)
        self.assertEqual(provider.lookup_calls, 1)
        self.assertEqual(provider.publish_calls, 1)

    def test_missing_publication_is_published(self) -> None:
        provider = FakeRecoverableProvider()

        receipt = recover_or_publish_anchor(
            provider,
            self.anchor,
        )

        self.assertEqual(
            receipt.anchor_digest,
            self.anchor.digest,
        )
        self.assertEqual(provider.lookup_calls, 1)
        self.assertEqual(provider.publish_calls, 1)
        self.assertIn(self.anchor.digest, provider.records)

    def test_repeated_recovery_does_not_create_new_record(self) -> None:
        provider = FakeRecoverableProvider()

        first = recover_or_publish_anchor(
            provider,
            self.anchor,
        )

        second = recover_or_publish_anchor(
            provider,
            self.anchor,
        )

        self.assertEqual(first, second)
        self.assertEqual(provider.publish_calls, 1)
        self.assertEqual(len(provider.records), 1)

    def test_invalid_anchor_is_rejected(self) -> None:
        provider = FakeRecoverableProvider()

        with self.assertRaisesRegex(
            TrustedAnchorRecoveryError,
            "valid SecurityCheckpointAnchor",
        ):
            recover_or_publish_anchor(
                provider,
                None,  # type: ignore[arg-type]
            )

        self.assertEqual(provider.lookup_calls, 0)
        self.assertEqual(provider.publish_calls, 0)

    def test_lookup_failure_fails_closed(self) -> None:
        class BrokenLookupProvider(FakeRecoverableProvider):
            def lookup_by_idempotency_key(
                self,
                idempotency_key: str,
            ) -> TrustedAnchorReceipt | None:
                raise OSError("simulated lookup outage")

        provider = BrokenLookupProvider()

        with self.assertRaisesRegex(
            TrustedAnchorRecoveryError,
            "Unable to look up",
        ):
            recover_or_publish_anchor(
                provider,
                self.anchor,
            )

        self.assertEqual(provider.publish_calls, 0)

    def test_invalid_recovered_digest_is_rejected(self) -> None:
        provider = FakeRecoverableProvider()

        wrong_anchor = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=7,
            last_hash="d" * 64,
        )

        wrong_receipt = create_signed_receipt(
            provider_id="test-recovery-provider",
            anchor_digest=wrong_anchor.digest,
            external_reference="wrong-record",
            observed_at="2026-10-30T00:00:00Z",
            secret=SECRET,
        )

        provider.records[self.anchor.digest] = wrong_receipt

        with self.assertRaisesRegex(
            TrustedAnchorRecoveryError,
            "digest does not match",
        ):
            recover_or_publish_anchor(
                provider,
                self.anchor,
            )

        self.assertEqual(provider.publish_calls, 0)

    def test_unverified_recovered_receipt_is_rejected(self) -> None:
        provider = FakeRecoverableProvider(
            verification_result=False,
        )

        provider.publish_idempotent(
            self.anchor,
            self.anchor.digest,
        )

        with self.assertRaisesRegex(
            TrustedAnchorRecoveryError,
            "was not verified",
        ):
            recover_or_publish_anchor(
                provider,
                self.anchor,
            )

        self.assertEqual(provider.publish_calls, 1)


if __name__ == "__main__":
    unittest.main()
