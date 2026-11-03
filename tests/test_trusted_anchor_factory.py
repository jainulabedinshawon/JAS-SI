from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.config import Settings
from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_factory import (
    create_trusted_anchor_provider,
)
from jas_si_agent.trusted_anchor_hmac import create_signed_receipt
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorProviderError,
    TrustedAnchorReceipt,
    publish_and_verify_anchor,
)


SECRET = b"jas-si-factory-test-secret-at-least-32-bytes"


class FakeBackend:
    """Test double only; not a real external anchor service."""

    def publish(
        self,
        anchor: SecurityCheckpointAnchor,
    ) -> TrustedAnchorReceipt:
        return create_signed_receipt(
            provider_id="test-provider",
            anchor_digest=anchor.digest,
            external_reference="factory-test-record",
            observed_at="2026-10-30T00:00:00Z",
            secret=SECRET,
        )

    def verify(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ) -> bool:
        return receipt.anchor_digest == anchor.digest


class TestTrustedAnchorFactory(unittest.TestCase):
    def setUp(self) -> None:
        self.anchor = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=5,
            last_hash="b" * 64,
        )

    def test_factory_builds_provider_from_settings(self) -> None:
        settings = Settings(
            trusted_anchor_hmac_secret=SECRET,
            trusted_anchor_provider_id="test-provider",
        )

        provider = create_trusted_anchor_provider(
            settings,
            FakeBackend(),
        )

        receipt = publish_and_verify_anchor(
            provider,
            self.anchor,
        )

        self.assertEqual(
            receipt.anchor_digest,
            self.anchor.digest,
        )

    def test_missing_credentials_fail_closed(self) -> None:
        settings = Settings()

        with self.assertRaisesRegex(
            TrustedAnchorProviderError,
            "credentials are not configured",
        ):
            create_trusted_anchor_provider(
                settings,
                FakeBackend(),
            )

    def test_missing_secret_fails_closed(self) -> None:
        settings = Settings(
            trusted_anchor_provider_id="test-provider",
        )

        with self.assertRaises(TrustedAnchorProviderError):
            create_trusted_anchor_provider(
                settings,
                FakeBackend(),
            )

    def test_missing_provider_id_fails_closed(self) -> None:
        settings = Settings(
            trusted_anchor_hmac_secret=SECRET,
        )

        with self.assertRaises(TrustedAnchorProviderError):
            create_trusted_anchor_provider(
                settings,
                FakeBackend(),
            )

    def test_invalid_backend_fails_closed(self) -> None:
        settings = Settings(
            trusted_anchor_hmac_secret=SECRET,
            trusted_anchor_provider_id="test-provider",
        )

        with self.assertRaisesRegex(
            TrustedAnchorProviderError,
            "valid Trusted Anchor backend",
        ):
            create_trusted_anchor_provider(
                settings,
                object(),  # type: ignore[arg-type]
            )

    def test_invalid_settings_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            TrustedAnchorProviderError,
            "Settings instance",
        ):
            create_trusted_anchor_provider(
                None,  # type: ignore[arg-type]
                FakeBackend(),
            )


if __name__ == "__main__":
    unittest.main()
