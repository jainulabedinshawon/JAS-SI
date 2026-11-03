from __future__ import annotations

import json
import unittest

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
    SecurityCheckpointAnchorError,
    verify_anchor_successor,
)


class TestSecurityCheckpointAnchorContract(unittest.TestCase):
    def setUp(self) -> None:
        self.anchor = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=3,
            last_hash="a" * 64,
        )

    def test_digest_is_deterministic(self) -> None:
        duplicate = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=3,
            last_hash="a" * 64,
        )
        self.assertEqual(self.anchor.digest, duplicate.digest)

    def test_changed_event_count_changes_digest(self) -> None:
        changed = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=4,
            last_hash="a" * 64,
        )
        self.assertNotEqual(self.anchor.digest, changed.digest)

    def test_changed_last_hash_changes_digest(self) -> None:
        changed = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=3,
            last_hash="b" * 64,
        )
        self.assertNotEqual(self.anchor.digest, changed.digest)

    def test_previous_anchor_is_bound_into_digest(self) -> None:
        changed = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=4,
            last_hash="b" * 64,
            previous_anchor_digest=self.anchor.digest,
        )
        unlinked = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=4,
            last_hash="b" * 64,
        )
        self.assertNotEqual(changed.digest, unlinked.digest)

    def test_round_trip_json(self) -> None:
        restored = SecurityCheckpointAnchor.from_json(
            self.anchor.to_json()
        )
        self.assertEqual(restored, self.anchor)
        self.assertEqual(restored.digest, self.anchor.digest)

    def test_rejects_invalid_hash(self) -> None:
        with self.assertRaises(SecurityCheckpointAnchorError):
            SecurityCheckpointAnchor(
                repository_id="JAS-SI",
                event_count=3,
                last_hash="short",
            )

    def test_rejects_boolean_event_count(self) -> None:
        with self.assertRaises(SecurityCheckpointAnchorError):
            SecurityCheckpointAnchor(
                repository_id="JAS-SI",
                event_count=True,
                last_hash="a" * 64,
            )

    def test_rejects_tampered_json_digest(self) -> None:
        record = json.loads(self.anchor.to_json())
        record["event_count"] = 99

        with self.assertRaises(SecurityCheckpointAnchorError):
            SecurityCheckpointAnchor.from_json(json.dumps(record))

    def test_rejects_extra_json_fields(self) -> None:
        record = json.loads(self.anchor.to_json())
        record["unexpected"] = "value"

        with self.assertRaises(SecurityCheckpointAnchorError):
            SecurityCheckpointAnchor.from_json(json.dumps(record))

    def test_accepts_valid_successor(self) -> None:
        current = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=5,
            last_hash="b" * 64,
            previous_anchor_digest=self.anchor.digest,
        )

        self.assertTrue(
            verify_anchor_successor(self.anchor, current)
        )

    def test_rejects_wrong_previous_anchor_digest(self) -> None:
        current = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=5,
            last_hash="b" * 64,
            previous_anchor_digest="c" * 64,
        )

        self.assertFalse(
            verify_anchor_successor(self.anchor, current)
        )

    def test_rejects_different_repository(self) -> None:
        current = SecurityCheckpointAnchor(
            repository_id="OTHER-REPO",
            event_count=5,
            last_hash="b" * 64,
            previous_anchor_digest=self.anchor.digest,
        )

        self.assertFalse(
            verify_anchor_successor(self.anchor, current)
        )

    def test_rejects_non_increasing_event_count(self) -> None:
        current = SecurityCheckpointAnchor(
            repository_id="JAS-SI",
            event_count=3,
            last_hash="b" * 64,
            previous_anchor_digest=self.anchor.digest,
        )

        self.assertFalse(
            verify_anchor_successor(self.anchor, current)
        )

    def test_rejects_non_anchor_inputs(self) -> None:
        self.assertFalse(
            verify_anchor_successor(self.anchor, object())
        )


if __name__ == "__main__":
    unittest.main()
