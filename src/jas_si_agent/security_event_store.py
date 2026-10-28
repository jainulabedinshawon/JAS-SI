"""Durable JSONL storage for API security events.

This is a security-event stream, separate from the hash-chained
action audit store. It does not execute actions and does not claim
to provide tamper-proof or independently anchored storage.
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
import threading
from pathlib import Path
from typing import Any, Mapping


class SecurityEventStoreError(ValueError):
    """Raised when a security event cannot be safely persisted."""


class JsonlSecurityEventStore:
    """Append JSON security events using restrictive file permissions."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, event: Mapping[str, Any]) -> None:
        """Validate and durably append one JSON event."""
        if not isinstance(event, Mapping):
            raise SecurityEventStoreError(
                "Event must be a mapping"
            )

        try:
            payload = (
                json.dumps(
                    dict(event),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise SecurityEventStoreError(
                "Event is not valid JSON data"
            ) from exc

        if len(payload) > 64 * 1024:
            raise SecurityEventStoreError(
                "Security event exceeds 64 KiB"
            )

        with self._lock:
            self._append_bytes(payload)

    def _append_bytes(self, payload: bytes) -> None:
        fd = -1
        lock_acquired = False

        try:
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
                mode=0o700,
            )

            if self.path.is_symlink():
                raise SecurityEventStoreError(
                    "Symlink security log files are not allowed"
                )

            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND

            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW

            fd = os.open(self.path, flags, 0o600)

            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise SecurityEventStoreError(
                    "Security log path must be a regular file"
                )

            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)

            # Serialize appends from cooperating processes that share
            # this file on a POSIX filesystem.
            fcntl.flock(fd, fcntl.LOCK_EX)
            lock_acquired = True

            remaining = memoryview(payload)

            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("Incomplete security log write")
                remaining = remaining[written:]

            os.fsync(fd)

        except SecurityEventStoreError:
            raise
        except (OSError, UnicodeError, ValueError) as exc:
            raise SecurityEventStoreError(
                "Unable to persist security event"
            ) from exc
        finally:
            if fd >= 0:
                if lock_acquired:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except OSError:
                        pass

                try:
                    os.close(fd)
                except OSError:
                    pass

    def load_events(self) -> tuple[dict[str, Any], ...]:
        """Read JSONL events after validating file type and JSON syntax."""
        try:
            if self.path.is_symlink():
                raise SecurityEventStoreError(
                    "Symlink security log files are not allowed"
                )

            if not self.path.exists():
                return ()

            if not stat.S_ISREG(self.path.stat().st_mode):
                raise SecurityEventStoreError(
                    "Security log path must be a regular file"
                )

            events: list[dict[str, Any]] = []

            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        raise SecurityEventStoreError(
                            f"Blank event at line {line_number}"
                        )

                    try:
                        item = json.loads(line)
                    except (json.JSONDecodeError, RecursionError) as exc:
                        raise SecurityEventStoreError(
                            f"Invalid JSON at line {line_number}"
                        ) from exc

                    if not isinstance(item, dict):
                        raise SecurityEventStoreError(
                            f"Event at line {line_number} must be an object"
                        )

                    events.append(item)

            return tuple(events)

        except SecurityEventStoreError:
            raise
        except (OSError, UnicodeError, RecursionError) as exc:
            raise SecurityEventStoreError(
                "Unable to read security event log"
            ) from exc
