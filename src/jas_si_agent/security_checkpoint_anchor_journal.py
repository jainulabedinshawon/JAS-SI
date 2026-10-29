
from __future__ import annotations

import fcntl
import os
import stat
from pathlib import Path

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
    SecurityCheckpointAnchorError,
    verify_anchor_successor,
)


class SecurityCheckpointAnchorJournalError(ValueError):
    """Raised when the local anchor journal is invalid or unavailable."""


class SecurityCheckpointAnchorJournal:
    """Append and verify a locally persisted sequence of checkpoint anchors.

    This journal detects malformed records and broken sequences.
    It does not protect against an attacker who can rewrite the entire file.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    @staticmethod
    def _parse_records(data: bytes) -> tuple[SecurityCheckpointAnchor, ...]:
        if not data:
            return ()

        try:
            text = data.decode("utf-8")
        except UnicodeError as exc:
            raise SecurityCheckpointAnchorJournalError(
                "Journal is not valid UTF-8"
            ) from exc

        if not text.endswith("\n"):
            raise SecurityCheckpointAnchorJournalError(
                "Journal ends with an incomplete record"
            )

        anchors: list[SecurityCheckpointAnchor] = []

        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line:
                raise SecurityCheckpointAnchorJournalError(
                    f"Blank record at line {line_number}"
                )

            try:
                anchor = SecurityCheckpointAnchor.from_json(line)
            except SecurityCheckpointAnchorError as exc:
                raise SecurityCheckpointAnchorJournalError(
                    f"Invalid anchor at line {line_number}"
                ) from exc

            if not anchors:
                if anchor.previous_anchor_digest is not None:
                    raise SecurityCheckpointAnchorJournalError(
                        "First anchor must not reference a predecessor"
                    )
            elif not verify_anchor_successor(anchors[-1], anchor):
                raise SecurityCheckpointAnchorJournalError(
                    f"Broken anchor sequence at line {line_number}"
                )

            anchors.append(anchor)

        return tuple(anchors)

    def _open_locked(self) -> int:
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )

        if self.path.is_symlink():
            raise SecurityCheckpointAnchorJournalError(
                "Symlink journal files are not allowed"
            )

        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        try:
            fd = os.open(self.path, flags, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise SecurityCheckpointAnchorJournalError(
                    "Journal must be a regular file"
                )

            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            return fd
        except SecurityCheckpointAnchorJournalError:
            raise
        except OSError as exc:
            raise SecurityCheckpointAnchorJournalError(
                "Unable to open anchor journal"
            ) from exc

    @staticmethod
    def _read_all(fd: int) -> bytes:
        chunks: list[bytes] = []
        offset = 0

        while True:
            chunk = os.pread(fd, 64 * 1024, offset)
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)

        return b"".join(chunks)

    def append(self, anchor: SecurityCheckpointAnchor) -> None:
        if not isinstance(anchor, SecurityCheckpointAnchor):
            raise SecurityCheckpointAnchorJournalError(
                "Expected a SecurityCheckpointAnchor"
            )

        fd = self._open_locked()

        try:
            existing = self._parse_records(self._read_all(fd))

            if not existing:
                if anchor.previous_anchor_digest is not None:
                    raise SecurityCheckpointAnchorJournalError(
                        "First anchor must not reference a predecessor"
                    )
            elif not verify_anchor_successor(existing[-1], anchor):
                raise SecurityCheckpointAnchorJournalError(
                    "New anchor is not a valid successor"
                )

            payload = (anchor.to_json() + "\n").encode("utf-8")
            os.lseek(fd, 0, os.SEEK_END)

            remaining = memoryview(payload)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("Incomplete journal write")
                remaining = remaining[written:]

            os.fsync(fd)

        except SecurityCheckpointAnchorJournalError:
            raise
        except OSError as exc:
            raise SecurityCheckpointAnchorJournalError(
                "Unable to append anchor"
            ) from exc
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def load(self) -> tuple[SecurityCheckpointAnchor, ...]:
        fd = self._open_locked()

        try:
            return self._parse_records(self._read_all(fd))
        except SecurityCheckpointAnchorJournalError:
            raise
        except OSError as exc:
            raise SecurityCheckpointAnchorJournalError(
                "Unable to read anchor journal"
            ) from exc
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
