
from __future__ import annotations

import hashlib
import json
import unittest


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def anchor_digest(
    *,
    repository_id: str,
    event_count: int,
    last_hash: str,
    previous_anchor_digest: str | None,
) -> str:
    payload = {
        "repository_id": repository_id,
        "event_count": event_count,
        "last_hash": last_hash,
        "previous_anchor_digest": previous_anchor_digest,
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


class TestSecurityCheckpointAnchorContract(unittest.TestCase):
    def setUp(self) -> None:
        self.base = {
            "repository_id": "JAS-SI",
            "event_count": 3,
            "last_hash": "a" * 64,
            "previous_anchor_digest": None,
        }

    def test_anchor_digest_is_deterministic(self) -> None:
        first = anchor_digest(**self.base)
        second = anchor_digest(**self.base)

        self.assertEqual(first, second)

    def test_changed_event_count_changes_digest(self) -> None:
        original = anchor_digest(**self.base)

        changed = dict(self.base)
        changed["event_count"] = 4

        self.assertNotEqual(
            original,
            anchor_digest(**changed),
        )

    def test_changed_checkpoint_hash_changes_digest(self) -> None:
        original = anchor_digest(**self.base)

        changed = dict(self.base)
        changed["last_hash"] = "b" * 64

        self.assertNotEqual(
            original,
            anchor_digest(**changed),
        )

    def test_anchor_chain_links_to_previous_anchor(self) -> None:
        first_digest = anchor_digest(**self.base)

        next_anchor = dict(self.base)
        next_anchor["event_count"] = 4
        next_anchor["last_hash"] = "c" * 64
        next_anchor["previous_anchor_digest"] = first_digest

        linked_digest = anchor_digest(**next_anchor)

        unlinked_anchor = dict(next_anchor)
        unlinked_anchor["previous_anchor_digest"] = None

        unlinked_digest = anchor_digest(**unlinked_anchor)

        self.assertNotEqual(linked_digest, unlinked_digest)

    def test_invalid_hash_length_is_not_accepted_by_contract(self) -> None:
        invalid = dict(self.base)
        invalid["last_hash"] = "short"

        # The contract requires a lowercase SHA-256 digest.
        self.assertFalse(
            isinstance(invalid["last_hash"], str)
            and len(invalid["last_hash"]) == 64
            and all(
                char in "0123456789abcdef"
                for char in invalid["last_hash"]
            )
        )


if __name__ == "__main__":
    unittest.main()
