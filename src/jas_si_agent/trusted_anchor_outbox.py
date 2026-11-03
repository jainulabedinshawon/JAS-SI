from __future__ import annotations

import fcntl
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)


class TrustedAnchorOutboxError(RuntimeError):
    """Raised when the durable trusted-anchor outbox is invalid."""


@dataclass(frozen=True)
class TrustedAnchorOutboxEntry:
    anchor: SecurityCheckpointAnchor
    status: str
    receipt: TrustedAnchorReceipt | None = None


class TrustedAnchorOutbox:
    """Append-only local outbox for trusted-anchor publication.

    Each state transition is persisted as a JSONL event and fsynced.
    This protects against ordinary process interruption, but not an
    attacker who can rewrite the entire outbox file.
    """

    MAX_BYTES = 16 * 1024 * 1024

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _open_locked(self) -> int:
        try:
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
                mode=0o700,
            )

            if self.path.is_symlink():
                raise TrustedAnchorOutboxError(
                    "Symlink outbox files are not allowed"
                )

            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW

            fd = os.open(self.path, flags, 0o600)

            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise TrustedAnchorOutboxError(
                    "Outbox must be a regular file"
                )

            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            return fd

        except TrustedAnchorOutboxError:
            raise
        except OSError as exc:
            raise TrustedAnchorOutboxError(
                "Unable to open trusted-anchor outbox"
            ) from exc

    @classmethod
    def _read_events(
        cls,
        fd: int,
    ) -> dict[str, TrustedAnchorOutboxEntry]:
        try:
            size = os.fstat(fd).st_size

            if size < 0 or size > cls.MAX_BYTES:
                raise TrustedAnchorOutboxError(
                    "Outbox exceeds the maximum allowed size"
                )

            chunks: list[bytes] = []
            offset = 0

            while offset < size:
                chunk = os.pread(
                    fd,
                    min(64 * 1024, size - offset),
                    offset,
                )
                if not chunk:
                    raise TrustedAnchorOutboxError(
                        "Outbox changed or ended unexpectedly"
                    )
                chunks.append(chunk)
                offset += len(chunk)

            data = b"".join(chunks)

        except OSError as exc:
            raise TrustedAnchorOutboxError(
                "Unable to read trusted-anchor outbox"
            ) from exc

        if not data:
            return {}

        try:
            text = data.decode("utf-8")
        except UnicodeError as exc:
            raise TrustedAnchorOutboxError(
                "Outbox is not valid UTF-8"
            ) from exc

        if not text.endswith("\n"):
            raise TrustedAnchorOutboxError(
                "Outbox ends with an incomplete record"
            )

        entries: dict[str, TrustedAnchorOutboxEntry] = {}

        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line:
                raise TrustedAnchorOutboxError(
                    f"Blank outbox record at line {line_number}"
                )

            try:
                event = json.loads(line)
            except (json.JSONDecodeError, RecursionError) as exc:
                raise TrustedAnchorOutboxError(
                    f"Invalid JSON at outbox line {line_number}"
                ) from exc

            if not isinstance(event, dict):
                raise TrustedAnchorOutboxError(
                    f"Invalid event at outbox line {line_number}"
                )

            if set(event) != {
                "anchor",
                "status",
                "receipt",
            }:
                raise TrustedAnchorOutboxError(
                    f"Unexpected event fields at line {line_number}"
                )

            try:
                anchor = SecurityCheckpointAnchor.from_json(
                    json.dumps(
                        event["anchor"],
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            except Exception as exc:
                raise TrustedAnchorOutboxError(
                    f"Invalid anchor at outbox line {line_number}"
                ) from exc

            status = event["status"]
            receipt_data = event["receipt"]

            if status == "PENDING":
                if receipt_data is not None:
                    raise TrustedAnchorOutboxError(
                        "Pending event must not contain a receipt"
                    )
                receipt = None

            elif status == "VERIFIED":
                if not isinstance(receipt_data, dict):
                    raise TrustedAnchorOutboxError(
                        "Verified event must contain a receipt"
                    )

                try:
                    receipt = TrustedAnchorReceipt(**receipt_data)
                except Exception as exc:
                    raise TrustedAnchorOutboxError(
                        "Invalid receipt in verified event"
                    ) from exc

                if receipt.anchor_digest != anchor.digest:
                    raise TrustedAnchorOutboxError(
                        "Outbox receipt digest mismatch"
                    )

            else:
                raise TrustedAnchorOutboxError(
                    "Unsupported outbox status"
                )

            previous = entries.get(anchor.digest)

            if previous is None:
                if status != "PENDING":
                    raise TrustedAnchorOutboxError(
                        "First outbox event must be PENDING"
                    )
            elif previous.status != "PENDING" or status != "VERIFIED":
                raise TrustedAnchorOutboxError(
                    "Invalid outbox state transition"
                )

            entries[anchor.digest] = TrustedAnchorOutboxEntry(
                anchor=anchor,
                status=status,
                receipt=receipt,
            )

        return entries

    @staticmethod
    def _event_bytes(
        anchor: SecurityCheckpointAnchor,
        status: str,
        receipt: TrustedAnchorReceipt | None,
    ) -> bytes:
        receipt_data = None

        if receipt is not None:
            receipt_data = {
                "provider_id": receipt.provider_id,
                "anchor_digest": receipt.anchor_digest,
                "external_reference": receipt.external_reference,
                "observed_at": receipt.observed_at,
                "proof": receipt.proof,
            }

        event = {
            "anchor": anchor.payload()
            | {"anchor_digest": anchor.digest},
            "status": status,
            "receipt": receipt_data,
        }

        return (
            json.dumps(
                event,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")

    def _append_locked(
        self,
        fd: int,
        payload: bytes,
    ) -> None:
        size = os.fstat(fd).st_size

        if size + len(payload) > self.MAX_BYTES:
            raise TrustedAnchorOutboxError(
                "Outbox exceeds the maximum allowed size"
            )

        os.lseek(fd, 0, os.SEEK_END)

        remaining = memoryview(payload)

        try:
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("Incomplete outbox write")
                remaining = remaining[written:]

            os.fsync(fd)

        except OSError as exc:
            raise TrustedAnchorOutboxError(
                "Unable to persist outbox event"
            ) from exc

    def prepare(
        self,
        anchor: SecurityCheckpointAnchor,
    ) -> TrustedAnchorOutboxEntry:
        """Persist PENDING before any external publication."""

        if not isinstance(anchor, SecurityCheckpointAnchor):
            raise TrustedAnchorOutboxError(
                "A valid SecurityCheckpointAnchor is required"
            )

        fd = self._open_locked()

        try:
            entries = self._read_events(fd)
            existing = entries.get(anchor.digest)

            if existing is not None:
                if existing.anchor != anchor:
                    raise TrustedAnchorOutboxError(
                        "Anchor digest collision detected"
                    )
                return existing

            self._append_locked(
                fd,
                self._event_bytes(anchor, "PENDING", None),
            )

            return TrustedAnchorOutboxEntry(
                anchor=anchor,
                status="PENDING",
            )

        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def mark_verified(
        self,
        anchor: SecurityCheckpointAnchor,
        receipt: TrustedAnchorReceipt,
    ) -> TrustedAnchorOutboxEntry:
        """Persist a verified receipt after independent verification."""

        if not isinstance(anchor, SecurityCheckpointAnchor):
            raise TrustedAnchorOutboxError(
                "A valid SecurityCheckpointAnchor is required"
            )

        if not isinstance(receipt, TrustedAnchorReceipt):
            raise TrustedAnchorOutboxError(
                "A valid TrustedAnchorReceipt is required"
            )

        if receipt.anchor_digest != anchor.digest:
            raise TrustedAnchorOutboxError(
                "Receipt digest does not match the anchor"
            )

        fd = self._open_locked()

        try:
            entries = self._read_events(fd)
            existing = entries.get(anchor.digest)

            if existing is None:
                raise TrustedAnchorOutboxError(
                    "Anchor must be prepared before verification"
                )

            if existing.status == "VERIFIED":
                if existing.receipt != receipt:
                    raise TrustedAnchorOutboxError(
                        "Anchor already has a different verified receipt"
                    )
                return existing

            self._append_locked(
                fd,
                self._event_bytes(
                    anchor,
                    "VERIFIED",
                    receipt,
                ),
            )

            return TrustedAnchorOutboxEntry(
                anchor=anchor,
                status="VERIFIED",
                receipt=receipt,
            )

        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def get(
        self,
        anchor_digest: str,
    ) -> TrustedAnchorOutboxEntry | None:
        """Read the latest persisted state for an anchor digest."""

        if (
            not isinstance(anchor_digest, str)
            or len(anchor_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in anchor_digest)
        ):
            raise TrustedAnchorOutboxError(
                "Invalid anchor digest"
            )

        fd = self._open_locked()

        try:
            return self._read_events(fd).get(anchor_digest)
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
