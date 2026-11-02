from __future__ import annotations

import re
import shutil
import subprocess

from dataclasses import dataclass
from typing import Optional, Tuple


MIN_OPENSSL_VERSION = (1, 1, 1)
VERSION_TIMEOUT_SECONDS = 5


class RFC3161RuntimeError(RuntimeError):
    """Raised when the RFC 3161 runtime is unavailable or unsafe."""


@dataclass(frozen=True)
class OpenSSLRuntimeStatus:
    available: bool
    executable: Optional[str]
    version: Optional[str]
    version_tuple: Optional[Tuple[int, int, int]]
    error: Optional[str]

    def require_available(self) -> "OpenSSLRuntimeStatus":
        """
        Fail closed if an acceptable OpenSSL runtime is unavailable.
        """
        if not self.available:
            raise RFC3161RuntimeError(
                self.error or "OpenSSL runtime is unavailable."
            )

        return self


def _parse_openssl_version(
    output: str,
) -> Optional[Tuple[int, int, int]]:
    """
    Parse an official OpenSSL version string.

    LibreSSL, BoringSSL, and unknown implementations are rejected.
    """
    if not output:
        return None

    match = re.search(
        r"^OpenSSL\s+(\d+)\.(\d+)\.(\d+)",
        output.strip(),
        flags=re.MULTILINE,
    )

    if not match:
        return None

    return tuple(
        int(part)
        for part in match.groups()
    )


def check_openssl_runtime(
    executable: Optional[str] = None,
    timeout: int = VERSION_TIMEOUT_SECONDS,
) -> OpenSSLRuntimeStatus:
    """
    Detect and validate the OpenSSL command-line runtime.

    Security properties:
    - No shell execution.
    - Fixed command arguments.
    - Bounded execution time.
    - No user-controlled command construction.
    - Explicit version validation.
    - Fail-closed behavior.
    """

    if timeout <= 0:
        return OpenSSLRuntimeStatus(
            available=False,
            executable=None,
            version=None,
            version_tuple=None,
            error="OpenSSL timeout must be positive.",
        )

    binary = executable or shutil.which("openssl")

    if not binary:
        return OpenSSLRuntimeStatus(
            available=False,
            executable=None,
            version=None,
            version_tuple=None,
            error="OpenSSL executable was not found.",
        )

    try:
        result = subprocess.run(
            [binary, "version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
            close_fds=True,
        )

    except subprocess.TimeoutExpired:
        return OpenSSLRuntimeStatus(
            available=False,
            executable=binary,
            version=None,
            version_tuple=None,
            error="OpenSSL version command timed out.",
        )

    except (OSError, subprocess.SubprocessError):
        return OpenSSLRuntimeStatus(
            available=False,
            executable=binary,
            version=None,
            version_tuple=None,
            error="OpenSSL version command could not be executed.",
        )

    if result.returncode != 0:
        return OpenSSLRuntimeStatus(
            available=False,
            executable=binary,
            version=None,
            version_tuple=None,
            error="OpenSSL version command returned a non-zero exit code.",
        )

    output = (result.stdout or "").strip()

    parsed_version = _parse_openssl_version(output)

    if parsed_version is None:
        return OpenSSLRuntimeStatus(
            available=False,
            executable=binary,
            version=output or None,
            version_tuple=None,
            error="Unrecognized or unsupported OpenSSL implementation.",
        )

    if parsed_version < MIN_OPENSSL_VERSION:
        return OpenSSLRuntimeStatus(
            available=False,
            executable=binary,
            version=output,
            version_tuple=parsed_version,
            error="OpenSSL version is below the supported minimum.",
        )

    return OpenSSLRuntimeStatus(
        available=True,
        executable=binary,
        version=output,
        version_tuple=parsed_version,
        error=None,
    )
