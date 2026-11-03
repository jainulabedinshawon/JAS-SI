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
from jas_si_agent.trusted_anchor_idempotency import (
    TrustedAnchorIdempotencyError,
    publish_and_verify_anchor_idempotently,
)


SECRET = b"jas-si-idempotency-test-secret-at-least-32-bytes"


class FakeIdempotentProvider:
    """Test double only; not a real external provider."""

    def __init__(self, verification_result: bool = True) -> None:
        self.verification_result = verification_result
        self.publications: dict[str, TrustedAnchorReceipt] = {}
        self.publish_calls = 0

    def publish_idempotent(
        self,
        anchor: SecurityCheckpointAnchor,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt:
        self.publish_calls += 1

        existing = self.publications.get(idempotency_key)

        if existing is not None:
            if existing.anchor_digest != anchor.digest:
                raise ValueError(
                    "Idempotency key reused with different anchor"
                )
            return existing

        receipt = create_signed_receipt(
            provider_id="test-idempotent-provider",
            anchor_digest=anchor.digest,
            external_reference=f"record-{idempotency_key[:12]}",
            observed_at="2026-10-30T00:00:00Z",
            secret=SECRET,
        )

        self.publications[idempotency_key] = receipt
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


class TestTrustedAnchorIdempotency(unittest.TestCase):

    def setUp(self) -> None:
        self.anchor = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=5,
            last_hash="b" * 64,
        )

    def test_idempotency_key_is_anchor_digest(self) -> None:
        provider = FakeIdempotentProvider()

        receipt = publish_and_verify_anchor_idempotently(
            provider,
            self.anchor,
        )

        self.assertEqual(
            receipt.anchor_digest,
            self.anchor.digest,
        )
        self.assertIn(
            self.anchor.digest,
            provider.publications,
        )

    def test_retry_returns_same_logical_receipt(self) -> None:
        provider = FakeIdempotentProvider()

        first = publish_and_verify_anchor_idempotently(
            provider,
            self.anchor,
        )

        second = publish_and_verify_anchor_idempotently(
            provider,
            self.anchor,
        )

        self.assertEqual(first, second)
        self.assertEqual(provider.publish_calls, 2)
        self.assertEqual(len(provider.publications), 1)

    def test_failed_verification_is_rejected(self) -> None:
        provider = FakeIdempotentProvider(
            verification_result=False,
        )

        with self.assertRaisesRegex(
            TrustedAnchorIdempotencyError,
            "was not verified",
        ):
            publish_and_verify_anchor_idempotently(
                provider,
                self.anchor,
            )

    def test_invalid_anchor_is_rejected(self) -> None:
        provider = FakeIdempotentProvider()

        with self.assertRaisesRegex(
            TrustedAnchorIdempotencyError,
            "valid SecurityCheckpointAnchor",
        ):
            publish_and_verify_anchor_idempotently(
                provider,
                None,  # type: ignore[arg-type]
            )

        self.assertEqual(provider.publish_calls, 0)

    def test_non_idempotent_provider_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            TrustedAnchorIdempotencyError,
            "idempotent anchor contract",
        ):
            publish_and_verify_anchor_idempotently(
                object(),  # type: ignore[arg-type]
                self.anchor,
            )

    def test_provider_exception_fails_closed(self) -> None:
        class BrokenProvider(FakeIdempotentProvider):
            def publish_idempotent(
                self,
                anchor: SecurityCheckpointAnchor,
                idempotency_key: str,
            ) -> TrustedAnchorReceipt:
                raise OSError("simulated provider outage")

        with self.assertRaisesRegex(
            TrustedAnchorIdempotencyError,
            "publication failed",
        ):
            publish_and_verify_anchor_idempotently(
                BrokenProvider(),
                self.anchor,
            )


if __name__ == "__main__":
    unittest.main()
