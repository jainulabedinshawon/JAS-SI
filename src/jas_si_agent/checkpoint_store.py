
"""Local persistent storage for JAS-SI audit checkpoints.

This module stores checkpoint anchors separately from the JSONL audit log.
A local checkpoint is not an independent or tamper-proof trust anchor.
This module never executes actions.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Sequence

from jas_si_agent.audit_checkpoint import (
    AuditCheckpoint,
    CheckpointError,
    create_checkpoint,
    verify_checkpoint,
)
from jas_si_agent.audit_log import AuditRecord


class CheckpointStoreError(ValueError):
    """Raised when checkpoint persistence or validation fails."""


class JsonCheckpointStore:
    """Persist one checkpoint using an atomic local-file replacement."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def save(self, checkpoint: AuditCheckpoint) -> None:
        """Atomically save a checkpoint with restrictive file permissions."""
        if not isinstance(checkpoint, AuditCheckpoint):
            raise CheckpointStoreError(
                "checkpoint must be an AuditCheckpoint"
            )

        temp_path: Path | None = None

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)

            if self.path.is_symlink():
                raise CheckpointStoreError(
                    "Symlink checkpoint files are not allowed"
                )

            fd, temp_name = tempfile.mkstemp(
                prefix=".checkpoint-",
                suffix=".tmp",
                dir=str(self.path.parent),
            )
            temp_path = Path(temp_name)

            try:
                os.fchmod(fd, 0o600)

                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    fd = -1
                    handle.write(checkpoint.to_json() + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                if fd >= 0:
                    os.close(fd)

            # Recheck immediately before replacement.
            if self.path.is_symlink():
                raise CheckpointStoreError(
                    "Symlink checkpoint files are not allowed"
                )

            os.replace(temp_path, self.path)
            temp_path = None

            # Persist the directory entry where supported.
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

        except CheckpointStoreError:
            raise
        except OSError as exc:
            raise CheckpointStoreError(
                "Unable to save checkpoint"
            ) from exc
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def load(self) -> AuditCheckpoint:
        """Load and validate a checkpoint from disk."""
        try:
            if self.path.is_symlink():
                raise CheckpointStoreError(
                    "Symlink checkpoint files are not allowed"
                )

            raw = self.path.read_text(encoding="utf-8")
            return AuditCheckpoint.from_json(raw)

        except CheckpointStoreError:
            raise
        except CheckpointError as exc:
            raise CheckpointStoreError(
                "Stored checkpoint is invalid"
            ) from exc
        except OSError as exc:
            raise CheckpointStoreError(
                "Unable to read checkpoint"
            ) from exc

    def create_and_save(
        self,
        records: Sequence[AuditRecord],
    ) -> AuditCheckpoint:
        """Validate a chain, create its checkpoint, and persist it."""
        try:
            checkpoint = create_checkpoint(records)
        except CheckpointError as exc:
            raise CheckpointStoreError(
                "Cannot checkpoint an invalid audit chain"
            ) from exc

        self.save(checkpoint)
        return checkpoint

    def verify_records(
        self,
        records: Sequence[AuditRecord],
    ) -> bool:
        """Compare records with the previously saved checkpoint."""
        try:
            checkpoint = self.load()
        except CheckpointStoreError:
            return False

        return verify_checkpoint(records, checkpoint)
