from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)
from tests.contracts.trusted_anchor_provider_contract import (
    TrustedAnchorProviderContractMixin,
)


class InMemoryContractProvider:
    """Thread-safe reference provider for contract testing only."""

    def __init__(self):
        self._lock = threading.Lock()
        self._records = {}
        self.logical_publications = 0

    def publish_idempotent(
        self,
        anchor: SecurityCheckpointAnchor,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt:
        if not isinstance(anchor, SecurityCheckpointAnchor):
            raise TypeError("Invalid anchor")

        if idempotency_key != anchor.digest:
            raise ValueError("Idempotency key must equal anchor digest")

        with self._lock:
            existing = self._records.get(idempotency_key)

            if existing is not None:
                if existing.anchor_digest != anchor.digest:
                    raise ValueError(
                        "Idempotency key reused for another anchor"
                    )
                return existing

            receipt = TrustedAnchorReceipt(
                provider_id="jas-si-reference-provider",
                anchor_digest=anchor.digest,
                external_reference=f"reference-{anchor.digest[:16]}",
                observed_at="2026-10-30T00:00:00Z",
                proof=f"reference-proof-{anchor.digest}",
            )

            self._records[idempotency_key] = receipt
            self.logical_publications += 1

            return receipt

    def lookup_by_idempotency_key(
        self,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt | None:
        with self._lock:
            return self._records.get(idempotency_key)

    def verify(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ) -> bool:
        if not isinstance(anchor, SecurityCheckpointAnchor):
            return False

        if not isinstance(receipt, TrustedAnchorReceipt):
            return False

        with self._lock:
            stored = self._records.get(anchor.digest)

            return (
                stored is not None
                and stored == receipt
                and receipt.anchor_digest == anchor.digest
            )


class ReferenceProviderContractTests(
    TrustedAnchorProviderContractMixin,
    unittest.TestCase,
):
    def make_provider(self):
        return InMemoryContractProvider()

    def make_anchor(
        self,
        event_count: int,
        last_hash: str,
    ) -> SecurityCheckpointAnchor:
        return SecurityCheckpointAnchor(
            repository_id="jainulabedinshawon/JAS-SI",
            event_count=event_count,
            last_hash=last_hash,
        )

    def test_reference_provider_creates_one_logical_publication(self):
        self.provider.publish_idempotent(
            self.anchor,
            self.idempotency_key,
        )
        self.provider.publish_idempotent(
            self.anchor,
            self.idempotency_key,
        )

        self.assertEqual(
            self.provider.logical_publications,
            1,
        )


if __name__ == "__main__":
    unittest.main()
