
from __future__ import annotations

import math
import re
import subprocess
import tempfile

from dataclasses import dataclass
from pathlib import Path

from jas_si_agent.rfc3161_request import RFC3161TimestampRequest
from jas_si_agent.rfc3161_response import RFC3161Response
from jas_si_agent.rfc3161_runtime import (
    RFC3161RuntimeError,
    check_openssl_runtime,
)


DEFAULT_TIMEOUT_SECONDS = 10
_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class RFC3161VerificationError(RuntimeError):
    """Raised when RFC 3161 verification input is invalid."""


@dataclass(frozen=True)
class RFC3161VerificationResult:
    status: str
    cryptographic_valid: bool | None
    digest_hex: str
    tsa_url: str
    openssl_version: str
    error: str | None = None


def verify_timestamp_response(
    response: RFC3161Response,
    request: RFC3161TimestampRequest,
    expected_digest_hex: str,
    *,
    trust_store: str | Path,
    openssl_executable: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> RFC3161VerificationResult:
    """
    Verify an RFC 3161 response using OpenSSL.

    This stage checks the timestamp response against the
    original request and an explicitly configured trust store.

    Overall status remains INDETERMINATE until the remaining
    JAS-SI policy, temporal and revocation checks are completed.
    """

    if not isinstance(response, RFC3161Response):
        raise RFC3161VerificationError(
            "A valid RFC3161Response is required."
        )

    if not isinstance(request, RFC3161TimestampRequest):
        raise RFC3161VerificationError(
            "A valid RFC3161TimestampRequest is required."
        )

    if not isinstance(response.response_bytes, bytes) or not response.response_bytes:
        raise RFC3161VerificationError(
            "Timestamp response bytes must be non-empty."
        )

    if response.status_code != 200:
        raise RFC3161VerificationError(
            "Timestamp response HTTP status must be 200."
        )

    content_type = response.content_type.split(";")[0].strip().lower()

    if content_type != "application/timestamp-reply":
        raise RFC3161VerificationError(
            "Unexpected RFC 3161 response content type."
        )

    if not isinstance(request.request_bytes, bytes) or not request.request_bytes:
        raise RFC3161VerificationError(
            "Original timestamp request bytes are required."
        )

    if request.digest_algorithm.lower() != "sha256":
        raise RFC3161VerificationError(
            "Only SHA-256 requests are currently supported."
        )

    if (
        not isinstance(expected_digest_hex, str)
        or not _SHA256_PATTERN.fullmatch(expected_digest_hex)
    ):
        raise RFC3161VerificationError(
            "Expected digest must be a 64-character SHA-256 hex string."
        )

    normalized_digest = expected_digest_hex.lower()

    if request.digest_hex.lower() != normalized_digest:
        raise RFC3161VerificationError(
            "Expected digest does not match the original request."
        )

    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or timeout <= 0
    ):
        raise RFC3161VerificationError(
            "Timeout must be a positive integer."
        )

    if not isinstance(response.tsa_url, str) or not response.tsa_url:
        raise RFC3161VerificationError(
            "TSA URL is required."
        )

    if not isinstance(trust_store, (str, Path)):
        raise RFC3161VerificationError(
            "An explicit trust-store path is required."
        )

    trust_path = Path(trust_store)

    if not trust_path.is_file() or not trust_path.stat().st_size:
        raise RFC3161VerificationError(
            "Configured trust store is missing or empty."
        )

    try:
        runtime = check_openssl_runtime(
            executable=openssl_executable,
            timeout=min(timeout, 5),
        )
        runtime.require_available()

    except RFC3161RuntimeError as exc:
        raise RFC3161VerificationError(
            "An acceptable OpenSSL runtime is required."
        ) from exc

    if not runtime.executable or not runtime.version:
        raise RFC3161VerificationError(
            "OpenSSL runtime information is incomplete."
        )

    try:
        with tempfile.TemporaryDirectory(
            prefix="jas-si-rfc3161-verify-"
        ) as temporary_directory:

            workdir = Path(temporary_directory)

            request_path = workdir / "request.tsq"
            response_path = workdir / "response.tsr"

            request_path.write_bytes(request.request_bytes)
            response_path.write_bytes(response.response_bytes)

            command = [
                runtime.executable,
                "ts",
                "-verify",
                "-queryfile",
                str(request_path),
                "-in",
                str(response_path),
                "-CAfile",
                str(trust_path.resolve()),
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
                return RFC3161VerificationResult(
                    status="INDETERMINATE",
                    cryptographic_valid=None,
                    digest_hex=normalized_digest,
                    tsa_url=response.tsa_url,
                    openssl_version=runtime.version,
                    error="OpenSSL could not establish timestamp validity.",
                )

            # This is only the cryptographic verification stage.
            # Final VALID requires all remaining specification gates.

            return RFC3161VerificationResult(
                status="INDETERMINATE",
                cryptographic_valid=True,
                digest_hex=normalized_digest,
                tsa_url=response.tsa_url,
                openssl_version=runtime.version,
            )

    except subprocess.TimeoutExpired as exc:
        raise RFC3161VerificationError(
            "RFC 3161 verification timed out."
        ) from exc

    except (OSError, subprocess.SubprocessError) as exc:
        raise RFC3161VerificationError(
            "RFC 3161 verification could not be completed."
        ) from exc
