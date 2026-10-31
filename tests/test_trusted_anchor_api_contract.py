from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.trusted_anchor_api_contract import (
    TrustedAnchorApiContract,
    TrustedAnchorApiContractError,
)


class TestTrustedAnchorApiContract(unittest.TestCase):
    def make_contract(self):
        return TrustedAnchorApiContract(
            publish_path="v1/anchors",
            lookup_path_template=(
                "v1/anchors/by-key/{idempotency_key}"
            ),
            idempotency_header="Idempotency-Key",
        )

    def test_valid_contract(self):
        contract = self.make_contract()

        self.assertEqual(contract.publish_path, "v1/anchors")
        self.assertEqual(
            contract.idempotency_header,
            "Idempotency-Key",
        )

    def test_lookup_path_uses_exact_key(self):
        contract = self.make_contract()
        key = "a" * 64

        self.assertEqual(
            contract.lookup_path(key),
            f"v1/anchors/by-key/{key}",
        )

    def test_rejects_absolute_publish_url(self):
        with self.assertRaises(TrustedAnchorApiContractError):
            TrustedAnchorApiContract(
                publish_path="https://example.com/v1/anchors",
                lookup_path_template="v1/lookup/{idempotency_key}",
                idempotency_header="Idempotency-Key",
            )

    def test_rejects_parent_directory_traversal(self):
        with self.assertRaises(TrustedAnchorApiContractError):
            TrustedAnchorApiContract(
                publish_path="v1/../admin",
                lookup_path_template="v1/lookup/{idempotency_key}",
                idempotency_header="Idempotency-Key",
            )

    def test_rejects_missing_lookup_placeholder(self):
        with self.assertRaises(TrustedAnchorApiContractError):
            TrustedAnchorApiContract(
                publish_path="v1/anchors",
                lookup_path_template="v1/lookup",
                idempotency_header="Idempotency-Key",
            )

    def test_rejects_multiple_lookup_placeholders(self):
        with self.assertRaises(TrustedAnchorApiContractError):
            TrustedAnchorApiContract(
                publish_path="v1/anchors",
                lookup_path_template=(
                    "v1/{idempotency_key}/{idempotency_key}"
                ),
                idempotency_header="Idempotency-Key",
            )

    def test_rejects_invalid_header_name(self):
        with self.assertRaises(TrustedAnchorApiContractError):
            TrustedAnchorApiContract(
                publish_path="v1/anchors",
                lookup_path_template="v1/lookup/{idempotency_key}",
                idempotency_header="Bad Header",
            )

    def test_rejects_non_2xx_status(self):
        with self.assertRaises(TrustedAnchorApiContractError):
            TrustedAnchorApiContract(
                publish_path="v1/anchors",
                lookup_path_template="v1/lookup/{idempotency_key}",
                idempotency_header="Idempotency-Key",
                success_status_codes=(200, 302),
            )

    def test_rejects_invalid_idempotency_key(self):
        contract = self.make_contract()

        with self.assertRaises(TrustedAnchorApiContractError):
            contract.lookup_path("../admin")

    def test_rejects_duplicate_status_codes(self):
        with self.assertRaises(TrustedAnchorApiContractError):
            TrustedAnchorApiContract(
                publish_path="v1/anchors",
                lookup_path_template="v1/lookup/{idempotency_key}",
                idempotency_header="Idempotency-Key",
                success_status_codes=(200, 200),
            )


if __name__ == "__main__":
    unittest.main()
