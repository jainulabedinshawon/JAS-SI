
from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)


class TrustedAnchorProviderContractMixin(unittest.TestCase):
    """Reusable conformance tests for recoverable idempotent providers.

    A concrete provider test must implement:
      - make_provider()
      - make_anchor(event_count, last_hash)

    The provider must implement:
      - publish_idempotent(anchor, idempotency_key)
      - lookup_by_idempotency_key(idempotency_key)
      - verify(anchor, receipt)
    """

    def make_provider(self):
        raise NotImplementedError

    def make_anchor(
        self,
        event_count: int,
        last_hash: str,
    ) -> SecurityCheckpointAnchor:
        raise NotImplementedError

    def setUp(self):
        self.provider = self.make_provider()
        self.anchor = self.make_anchor(1, "a" * 64)
        self.idempotency_key = self.anchor.digest

    def test_lookup_returns_none_before_publication(self):
        result = self.provider.lookup_by_idempotency_key(
            self.idempotency_key
        )

        self.assertIsNone(result)

    def test_publish_is_idempotent_for_same_key_and_anchor(self):
        first = self.provider.publish_idempotent(
            self.anchor,
            self.idempotency_key,
        )
        second = self.provider.publish_idempotent(
            self.anchor,
            self.idempotency_key,
        )

        self.assertIsInstance(first, TrustedAnchorReceipt)
        self.assertEqual(first, second)

    def test_lookup_returns_published_receipt(self):
        receipt = self.provider.publish_idempotent(
            self.anchor,
            self.idempotency_key,
        )

        recovered = self.provider.lookup_by_idempotency_key(
            self.idempotency_key
        )

        self.assertEqual(recovered, receipt)

    def test_same_key_with_different_anchor_is_rejected(self):
        self.provider.publish_idempotent(
            self.anchor,
            self.idempotency_key,
        )

        different_anchor = self.make_anchor(
            2,
            "b" * 64,
        )

        with self.assertRaises(Exception):
            self.provider.publish_idempotent(
                different_anchor,
                self.idempotency_key,
            )

        original = self.provider.lookup_by_idempotency_key(
            self.idempotency_key
        )

        self.assertEqual(
            original.anchor_digest,
            self.anchor.digest,
        )

    def test_wrong_idempotency_key_is_rejected(self):
        with self.assertRaises(Exception):
            self.provider.publish_idempotent(
                self.anchor,
                "0" * 64,
            )

    def test_concurrent_same_key_requests_create_one_receipt(self):
        def publish_once(_):
            return self.provider.publish_idempotent(
                self.anchor,
                self.idempotency_key,
            )

        with ThreadPoolExecutor(max_workers=8) as executor:
            receipts = list(
                executor.map(publish_once, range(24))
            )

        self.assertTrue(
            all(
                isinstance(receipt, TrustedAnchorReceipt)
                for receipt in receipts
            )
        )

        self.assertTrue(
            all(receipt == receipts[0] for receipt in receipts)
        )

        recovered = self.provider.lookup_by_idempotency_key(
            self.idempotency_key
        )

        self.assertEqual(recovered, receipts[0])

    def test_provider_verifies_its_published_receipt(self):
        receipt = self.provider.publish_idempotent(
            self.anchor,
            self.idempotency_key,
        )

        self.assertIs(
            self.provider.verify(self.anchor, receipt),
            True,
        )

    def test_provider_rejects_receipt_for_another_anchor(self):
        receipt = self.provider.publish_idempotent(
            self.anchor,
            self.idempotency_key,
        )

        different_anchor = self.make_anchor(
            3,
            "c" * 64,
        )

        self.assertIs(
            self.provider.verify(different_anchor, receipt),
            False,
        )
