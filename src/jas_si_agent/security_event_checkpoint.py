
"""Persist and verify checkpoints for the security event hash chain.

The checkpoint should be retained independently of the event log whenever
protection against full-log rollback or rewriting is required.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from jas_si_agent.security_event_store import (
    JsonlSecurityEventStore,
    SecurityEventStoreError,
)

_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class SecurityCheckpointError(ValueError):
    """Raised when a security checkpoint is invalid or cannot be persisted."""


@dataclass(frozen=True)
class SecurityEventCheckpoint:
    event_count: int
    last_hash: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.event_count, int)
            or isinstance(self.event_count, bool)
            or self.event_count < 1
        ):
            raise SecurityCheckpointError(
                "event_count must be a positive integer"
            )

        if (
            not isinstance(self.last_hash, str)
            or not _HASH_PATTERN.fullmatch(self.last_hash)
        ):
            raise SecurityCheckpointError(
                "last_hash must be a lowercase SHA-256 hash"
            )

    def to_json(self) -> str:
        """Serialize checkpoint fields in a deterministic format."""
        return json.dumps(
            {
                "event_count": self.event_count,
                "last_hash": self.last_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, value: str) -> "SecurityEventCheckpoint":
        """Parse a checkpoint, rejecting unexpected fields."""
        try:
            data = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise SecurityCheckpointError(
                "Invalid checkpoint JSON"
            ) from exc

        if not isinstance(data, dict):
            raise SecurityCheckpointError(
                "Checkpoint must be a JSON object"
            )

        if set(data) != {"event_count", "last_hash"}:
            raise SecurityCheckpointError(
                "Unexpected or missing checkpoint fields"
            )

        return cls(
            event_count=data["event_count"],
            last_hash=data["last_hash"],
        )


def create_security_checkpoint(
    store: JsonlSecurityEventStore,
) -> SecurityEventCheckpoint:
    """Create a checkpoint only after strict chain verification."""
    report = store.verify_integrity(require_chain=True)

    return SecurityEventCheckpoint(
        event_count=report["verified_event_count"],
        last_hash=report["last_hash"],
    )


def save_security_checkpoint(
    path: str | Path,
    checkpoint: SecurityEventCheckpoint,
) -> None:
    """Atomically persist a checkpoint with restrictive file permissions."""
    if not isinstance(checkpoint, SecurityEventCheckpoint):
        raise SecurityCheckpointError("Invalid checkpoint object")

    target = Path(path)
    temporary_path: Path | None = None

    try:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        if target.is_symlink():
            raise SecurityCheckpointError(
                "Symlink checkpoint files are not allowed"
            )

        fd, temporary_name = tempfile.mkstemp(
            prefix=".checkpoint-",
            suffix=".tmp",
            dir=target.parent,
        )
        temporary_path = Path(temporary_name)

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(checkpoint.to_json())
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary_path, target)
        temporary_path = None

        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    except SecurityCheckpointError:
        raise
    except (OSError, ValueError) as exc:
        raise SecurityCheckpointError(
            "Unable to persist security checkpoint"
        ) from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def load_security_checkpoint(
    path: str | Path,
) -> SecurityEventCheckpoint:
    """Load and validate a persisted checkpoint."""
    target = Path(path)

    try:
        if target.is_symlink():
            raise SecurityCheckpointError(
                "Symlink checkpoint files are not allowed"
            )

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        fd = os.open(target, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise SecurityCheckpointError(
                    "Checkpoint path must be a regular file"
                )

            with os.fdopen(fd, "r", encoding="utf-8") as handle:
                fd = -1
                content = handle.read(4096)

                if len(content) == 4096:
                    raise SecurityCheckpointError(
                        "Checkpoint file is too large"
                    )
        finally:
            if fd >= 0:
                os.close(fd)

        return SecurityEventCheckpoint.from_json(content)

    except SecurityCheckpointError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise SecurityCheckpointError(
            "Unable to load security checkpoint"
        ) from exc


def verify_security_checkpoint(
    store: JsonlSecurityEventStore,
    checkpoint: SecurityEventCheckpoint,
) -> bool:
    """Require the current log to match the saved checkpoint exactly."""
    if not isinstance(checkpoint, SecurityEventCheckpoint):
        return False

    try:
        report = store.verify_integrity(
            require_chain=True,
            expected_last_hash=checkpoint.last_hash,
        )
    except SecurityEventStoreError:
        return False

    return report["verified_event_count"] == checkpoint.event_count
