
from __future__ import annotations

import re
import subprocess
import tempfile

from dataclasses import dataclass
from pathlib import Path

from jas_si_agent.rfc3161_runtime import (
    RFC3161RuntimeError,
    check_openssl_runtime,
)


DEFAULT_MAX_REQUEST_BYTES = 16384
DEFAULT_TIMEOUT_SECONDS = 10

_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class RFC3161RequestError(RuntimeError):
    """Raised when an RFC 3161 request cannot be safely created."""


@dataclass(frozen=True)
class RFC3161TimestampRequest:
    request_bytes: bytes
    digest_algorithm: str
    digest_hex: str
    openssl_version: str

    @property
    def request_size(self) -> int:
        return len(self.request_bytes)


def create_timestamp_request(
    checkpoint_digest: str,
    *,
    openssl_executable: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
) -> RFC3161TimestampRequest:
    """
    Create an RFC 3161 DER timestamp request using OpenSSL.

    SHA-256 is the only enabled algorithm in this implementation.
    OpenSSL generates the ASN.1/DER request and its nonce.
    The original DER request bytes are preserved for verification.
    """

    if not isinstance(checkpoint_digest, str):
        raise RFC3161RequestError(
            "Checkpoint digest must be a hexadecimal string."
        )

    if not _SHA256_PATTERN.fullmatch(checkpoint_digest):
        raise RFC3161RequestError(
            "SHA-256 checkpoint digest must contain exactly 64 hexadecimal characters."
        )

    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise RFC3161RequestError(
            "Timeout must be a positive integer."
        )

    if timeout <= 0:
        raise RFC3161RequestError(
            "Timeout must be a positive integer."
        )

    if (
        not isinstance(max_request_bytes, int)
        or isinstance(max_request_bytes, bool)
        or not 1024 <= max_request_bytes <= 1048576
    ):
        raise RFC3161RequestError(
            "Maximum request size must be between 1024 and 1048576 bytes."
        )

    try:
        runtime = check_openssl_runtime(
            executable=openssl_executable,
            timeout=min(timeout, 5),
        )
        runtime.require_available()

    except RFC3161RuntimeError as exc:
        raise RFC3161RequestError(
            "An acceptable OpenSSL runtime is required."
        ) from exc

    if not runtime.executable or not runtime.version:
        raise RFC3161RequestError(
            "OpenSSL runtime information is incomplete."
        )

    normalized_digest = checkpoint_digest.lower()

    try:
        with tempfile.TemporaryDirectory(
            prefix="jas-si-rfc3161-"
        ) as temporary_directory:

            request_path = (
                Path(temporary_directory) / "request.tsq"
            )

            command = [
                runtime.executable,
                "ts",
                "-query",
                "-digest",
                normalized_digest,
                "-sha256",
                "-cert",
                "-out",
                str(request_path),
            ]

            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
                shell=False,
                close_fds=True,
                cwd=temporary_directory,
            )

            if result.returncode != 0:
                raise RFC3161RequestError(
                    "OpenSSL failed to create the timestamp request."
                )

            if not request_path.is_file():
                raise RFC3161RequestError(
                    "OpenSSL did not produce a request file."
                )

            request_size = request_path.stat().st_size

            if request_size <= 0:
                raise RFC3161RequestError(
                    "OpenSSL produced an empty timestamp request."
                )

            if request_size > max_request_bytes:
                raise RFC3161RequestError(
                    "Generated timestamp request exceeded the size limit."
                )

            request_bytes = request_path.read_bytes()

            if len(request_bytes) != request_size:
                raise RFC3161RequestError(
                    "Timestamp request changed while being read."
                )

            return RFC3161TimestampRequest(
                request_bytes=request_bytes,
                digest_algorithm="sha256",
                digest_hex=normalized_digest,
                openssl_version=runtime.version,
            )

    except RFC3161RequestError:
        raise

    except subprocess.TimeoutExpired as exc:
        raise RFC3161RequestError(
            "OpenSSL timestamp request generation timed out."
        ) from exc

    except (OSError, subprocess.SubprocessError) as exc:
        raise RFC3161RequestError(
            "OpenSSL timestamp request generation failed."
        ) from exc
