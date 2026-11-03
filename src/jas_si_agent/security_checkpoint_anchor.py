from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass


_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class SecurityCheckpointAnchorError(ValueError):
    """Raised when a checkpoint anchor is invalid."""


def canonical_json(value: object) -> bytes:
    """Return deterministic JSON bytes for hashing."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise SecurityCheckpointAnchorError(
            "Anchor payload is not valid canonical JSON"
        ) from exc


def _validate_digest(value: str, field_name: str) -> None:
    if (
        not isinstance(value, str)
        or not _HASH_PATTERN.fullmatch(value)
    ):
        raise SecurityCheckpointAnchorError(
            f"{field_name} must be a lowercase SHA-256 digest"
        )


@dataclass(frozen=True)
class SecurityCheckpointAnchor:
    repository_id: str
    event_count: int
    last_hash: str
    previous_anchor_digest: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.repository_id, str)
            or not self.repository_id.strip()
            or self.repository_id != self.repository_id.strip()
        ):
            raise SecurityCheckpointAnchorError(
                "repository_id must be a non-empty trimmed string"
            )

        if (
            not isinstance(self.event_count, int)
            or isinstance(self.event_count, bool)
            or self.event_count < 1
        ):
            raise SecurityCheckpointAnchorError(
                "event_count must be a positive integer"
            )

        _validate_digest(self.last_hash, "last_hash")

        if self.previous_anchor_digest is not None:
            _validate_digest(
                self.previous_anchor_digest,
                "previous_anchor_digest",
            )

    def payload(self) -> dict[str, object]:
        return {
            "repository_id": self.repository_id,
            "event_count": self.event_count,
            "last_hash": self.last_hash,
            "previous_anchor_digest": self.previous_anchor_digest,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.payload())).hexdigest()

    def to_json(self) -> str:
        record = self.payload()
        record["anchor_digest"] = self.digest
        return canonical_json(record).decode("utf-8")

    @classmethod
    def from_json(cls, value: str) -> "SecurityCheckpointAnchor":
        try:
            data = json.loads(value)
        except (TypeError, json.JSONDecodeError, RecursionError) as exc:
            raise SecurityCheckpointAnchorError(
                "Invalid anchor JSON"
            ) from exc

        expected_fields = {
            "repository_id",
            "event_count",
            "last_hash",
            "previous_anchor_digest",
            "anchor_digest",
        }

        if not isinstance(data, dict) or set(data) != expected_fields:
            raise SecurityCheckpointAnchorError(
                "Anchor has unexpected or missing fields"
            )

        recorded_digest = data["anchor_digest"]
        _validate_digest(recorded_digest, "anchor_digest")

        anchor = cls(
            repository_id=data["repository_id"],
            event_count=data["event_count"],
            last_hash=data["last_hash"],
            previous_anchor_digest=data["previous_anchor_digest"],
        )

        if anchor.digest != recorded_digest:
            raise SecurityCheckpointAnchorError(
                "Anchor digest verification failed"
            )

        return anchor


def verify_anchor_successor(
    previous: SecurityCheckpointAnchor,
    current: SecurityCheckpointAnchor,
) -> bool:
    """Verify that current is a valid successor to previous."""
    if not isinstance(previous, SecurityCheckpointAnchor):
        return False

    if not isinstance(current, SecurityCheckpointAnchor):
        return False

    if current.repository_id != previous.repository_id:
        return False

    if current.event_count <= previous.event_count:
        return False

    if current.previous_anchor_digest != previous.digest:
        return False

    return True
