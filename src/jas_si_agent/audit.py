
"""Hash-chained JSONL audit log for JAS-SI.

This detects accidental or unauthorized edits to records when the chain
is verified against a trusted prior hash. It is not a substitute for
remote immutable storage or externally anchored checkpoints.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, Mapping, Tuple

_ZERO_HASH = "0" * 64


class AuditLogError(RuntimeError):
    """Raised when an audit log cannot be verified or safely updated."""


def _canonical_json(value: Any) -> str:
    """Serialize deterministically for stable hashing."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _record_hash(
    sequence: int,
    previous_hash: str,
    event: Dict[str, Any],
) -> str:
    content = {
        "sequence": sequence,
        "previous_hash": previous_hash,
        "event": event,
    }
    return hashlib.sha256(_canonical_json(content).encode("utf-8")).hexdigest()


class HashChainAuditLog:
    """Append and verify hash-chained audit records in a JSONL file.

    Use one writer process per file. The thread lock protects concurrent
    calls through this instance, but is not a cross-process file lock.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._sequence = 0
        self._last_hash = _ZERO_HASH

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._sequence, self._last_hash = self._verify_file()

    def _verify_file(self) -> Tuple[int, str]:
        if not self.path.exists():
            return 0, _ZERO_HASH

        sequence = 0
        previous_hash = _ZERO_HASH

        try:
            with self.path.open("rb") as handle:
                content = handle.read()

            if content and not content.endswith(b"\n"):
                raise AuditLogError(
                    "Audit log has an incomplete final record"
                )

            for line_number, raw_line in enumerate(
                content.splitlines(), start=1
            ):
                if not raw_line:
                    raise AuditLogError(
                        f"Empty audit record at line {line_number}"
                    )

                try:
                    record = json.loads(raw_line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise AuditLogError(
                        f"Invalid JSON at line {line_number}"
                    ) from exc

                if not isinstance(record, dict):
                    raise AuditLogError(
                        f"Record at line {line_number} is not an object"
                    )

                expected_keys = {
                    "sequence",
                    "previous_hash",
                    "event",
                    "entry_hash",
                }
                if set(record) != expected_keys:
                    raise AuditLogError(
                        f"Unexpected record schema at line {line_number}"
                    )

                expected_sequence = sequence + 1
                if record["sequence"] != expected_sequence:
                    raise AuditLogError(
                        f"Invalid sequence at line {line_number}"
                    )

                if record["previous_hash"] != previous_hash:
                    raise AuditLogError(
                        f"Broken hash link at line {line_number}"
                    )

                event = record["event"]
                if not isinstance(event, dict):
                    raise AuditLogError(
                        f"Invalid event at line {line_number}"
                    )

                calculated_hash = _record_hash(
                    expected_sequence,
                    previous_hash,
                    event,
                )
                if record["entry_hash"] != calculated_hash:
                    raise AuditLogError(
                        f"Hash mismatch at line {line_number}"
                    )

                sequence = expected_sequence
                previous_hash = calculated_hash

        except OSError as exc:
            raise AuditLogError("Could not read audit log") from exc

        return sequence, previous_hash

    def append(self, event: Mapping[str, Any]) -> Dict[str, Any]:
        """Append one JSON-serializable event and return its chain record."""
        if not isinstance(event, Mapping):
            raise TypeError("event must be a mapping")

        # Copy and validate before changing the file.
        try:
            safe_event = json.loads(_canonical_json(dict(event)))
        except (TypeError, ValueError) as exc:
            raise AuditLogError(
                "Event must contain only valid JSON values"
            ) from exc

        with self._lock:
            # Detect external edits since this instance last wrote.
            sequence, previous_hash = self._verify_file()
            if (
                sequence != self._sequence
                or previous_hash != self._last_hash
            ):
                raise AuditLogError(
                    "Audit log changed since last verified write"
                )

            next_sequence = sequence + 1
            entry_hash = _record_hash(
                next_sequence,
                previous_hash,
                safe_event,
            )
            record = {
                "sequence": next_sequence,
                "previous_hash": previous_hash,
                "event": safe_event,
                "entry_hash": entry_hash,
            }
            line = _canonical_json(record) + "\n"

            try:
                with self.path.open("ab") as handle:
                    handle.write(line.encode("utf-8"))
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as exc:
                raise AuditLogError("Could not append audit record") from exc

            self._sequence = next_sequence
            self._last_hash = entry_hash
            return record

    def verify(self) -> Dict[str, Any]:
        """Verify the file and return its record count and terminal hash."""
        with self._lock:
            sequence, last_hash = self._verify_file()
            if (
                sequence != self._sequence
                or last_hash != self._last_hash
            ):
                raise AuditLogError(
                    "Audit log changed since last verified write"
                )

            return {
                "valid": True,
                "records": sequence,
                "last_hash": last_hash,
            }
