"""Durable JSONL storage for API security events with hash-chain checks.

Legacy events without integrity metadata remain readable, but are not
cryptographically covered by the hash chain. Hash chaining is not a
substitute for independently anchored storage.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import stat
import threading
from pathlib import Path
from typing import Any, Mapping


GENESIS_HASH = "0" * 64
INTEGRITY_KEY = "_integrity"
MAX_EVENT_BYTES = 64 * 1024


class SecurityEventStoreError(ValueError):
    """Raised when a security event cannot be safely persisted."""


def _canonical_json(value: Any) -> bytes:
    """Serialize JSON deterministically for hashing."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _event_hash(event: dict[str, Any], previous_hash: str) -> str:
    """Calculate the hash for one event and its predecessor."""
    material = {
        "event": event,
        "previous_hash": previous_hash,
    }
    return hashlib.sha256(_canonical_json(material)).hexdigest()


def _parse_log(data: bytes) -> dict[str, Any]:
    """Parse records and verify the integrity chain, if present."""
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise SecurityEventStoreError(
            "Security event log is not valid UTF-8"
        ) from exc

    events: list[dict[str, Any]] = []
    legacy_count = 0
    verified_count = 0
    previous_hash = GENESIS_HASH
    chain_started = False

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise SecurityEventStoreError(
                f"Blank event at line {line_number}"
            )

        try:
            record = json.loads(line)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise SecurityEventStoreError(
                f"Invalid JSON at line {line_number}"
            ) from exc

        if not isinstance(record, dict):
            raise SecurityEventStoreError(
                f"Event at line {line_number} must be an object"
            )

        metadata = record.pop(INTEGRITY_KEY, None)

        if metadata is None:
            if chain_started:
                raise SecurityEventStoreError(
                    f"Unchained event after hash chain at line {line_number}"
                )
            legacy_count += 1
            events.append(record)
            continue

        if not isinstance(metadata, dict):
            raise SecurityEventStoreError(
                f"Invalid integrity metadata at line {line_number}"
            )

        algorithm = metadata.get("algorithm")
        recorded_previous = metadata.get("previous_hash")
        recorded_hash = metadata.get("event_hash")

        if algorithm != "sha256":
            raise SecurityEventStoreError(
                f"Unsupported integrity algorithm at line {line_number}"
            )

        if not isinstance(recorded_previous, str) or not isinstance(
            recorded_hash, str
        ):
            raise SecurityEventStoreError(
                f"Missing integrity hash at line {line_number}"
            )

        if not hmac.compare_digest(recorded_previous, previous_hash):
            raise SecurityEventStoreError(
                f"Previous hash mismatch at line {line_number}"
            )

        expected_hash = _event_hash(record, previous_hash)
        if not hmac.compare_digest(recorded_hash, expected_hash):
            raise SecurityEventStoreError(
                f"Event hash mismatch at line {line_number}"
            )

        chain_started = True
        previous_hash = recorded_hash
        verified_count += 1
        events.append(record)

    return {
        "events": tuple(events),
        "legacy_event_count": legacy_count,
        "verified_event_count": verified_count,
        "last_hash": previous_hash,
    }


class JsonlSecurityEventStore:
    """Append security events using restrictive permissions and file locks."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, event: Mapping[str, Any]) -> None:
        """Validate, hash-chain, and durably append one event."""
        if not isinstance(event, Mapping):
            raise SecurityEventStoreError("Event must be a mapping")

        event_data = dict(event)
        if INTEGRITY_KEY in event_data:
            raise SecurityEventStoreError(
                f"Event key {INTEGRITY_KEY!r} is reserved"
            )

        try:
            event_bytes = _canonical_json(event_data)
        except (TypeError, ValueError, RecursionError) as exc:
            raise SecurityEventStoreError(
                "Event is not valid JSON data"
            ) from exc

        if len(event_bytes) + 1024 > MAX_EVENT_BYTES:
            raise SecurityEventStoreError(
                "Security event exceeds 64 KiB"
            )

        with self._lock:
            self._append_chained(event_data)

    def _append_chained(self, event: dict[str, Any]) -> None:
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

            flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW

            fd = os.open(self.path, flags, 0o600)

            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise SecurityEventStoreError(
                    "Security log path must be a regular file"
                )

            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            lock_acquired = True

            # Read and verify while holding the exclusive writer lock.
            os.lseek(fd, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, 64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)

            parsed = _parse_log(b"".join(chunks))
            previous_hash = parsed["last_hash"]
            new_hash = _event_hash(event, previous_hash)

            record = dict(event)
            record[INTEGRITY_KEY] = {
                "algorithm": "sha256",
                "previous_hash": previous_hash,
                "event_hash": new_hash,
            }

            payload = _canonical_json(record) + b"\n"
            if len(payload) > MAX_EVENT_BYTES:
                raise SecurityEventStoreError(
                    "Security event exceeds 64 KiB"
                )

            remaining = memoryview(payload)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("Incomplete security log write")
                remaining = remaining[written:]

            os.fsync(fd)

        except SecurityEventStoreError:
            raise
        except (OSError, UnicodeError, ValueError, RecursionError) as exc:
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

    def _read_log_bytes(self) -> bytes:
        fd = -1
        try:
            if self.path.is_symlink():
                raise SecurityEventStoreError(
                    "Symlink security log files are not allowed"
                )

            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW

            try:
                fd = os.open(self.path, flags)
            except FileNotFoundError:
                return b""

            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise SecurityEventStoreError(
                    "Security log path must be a regular file"
                )

            fcntl.flock(fd, fcntl.LOCK_SH)
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                return handle.read()

        except SecurityEventStoreError:
            raise
        except (OSError, UnicodeError) as exc:
            raise SecurityEventStoreError(
                "Unable to read security event log"
            ) from exc
        finally:
            if fd >= 0:
                os.close(fd)

    def load_events(self) -> tuple[dict[str, Any], ...]:
        """Return event payloads after verifying all available chain hashes."""
        return _parse_log(self._read_log_bytes())["events"]

    def verify_integrity(
        self,
        *,
        require_chain: bool = False,
    ) -> dict[str, Any]:
        """Verify the log, optionally requiring a complete hash chain."""
        parsed = _parse_log(self._read_log_bytes())

        if require_chain and (
            parsed["legacy_event_count"] > 0
            or parsed["verified_event_count"] == 0
        ):
            raise SecurityEventStoreError(
                "Strict integrity verification requires a complete "
                "hash chain with no legacy events"
            )

        return {
            "valid": True,
            "legacy_event_count": parsed["legacy_event_count"],
            "verified_event_count": parsed["verified_event_count"],
            "last_hash": parsed["last_hash"],
        }
