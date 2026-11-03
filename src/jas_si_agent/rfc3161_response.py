from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

from jas_si_agent.rfc3161_request import RFC3161Request


class RFC3161FetchError(Exception):
    """Raised when timestamp response acquisition fails."""
    pass


@dataclass(frozen=True)
class RFC3161Response:
    response_bytes: bytes
    tsa_url: str
    status_code: int
    content_type: str


def fetch_timestamp_response(
    request: RFC3161Request,
    tsa_url: str,
    timeout: float = 10.0,
    max_response_bytes: int = 65536,
) -> RFC3161Response:
    if not tsa_url or not (tsa_url.startswith("http://") or tsa_url.startswith("https://")):
        raise RFC3161FetchError("Invalid TSA URL scheme. Only http and https are allowed.")

    if timeout <= 0:
        raise RFC3161FetchError("Timeout must be a positive number.")

    headers = {
        "Content-Type": "application/timestamp-query",
        "Accept": "application/timestamp-reply",
        "User-Agent": "JAS-SI-Verify-Agent/0.1",
    }

    req = urllib.request.Request(
        url=tsa_url,
        data=request.request_bytes,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.getcode()
            content_type = resp.headers.get("Content-Type", "")

            if status_code != 200:
                raise RFC3161FetchError(f"TSA server returned unexpected HTTP status: {status_code}")

            body = resp.read(max_response_bytes + 1)
            if len(body) > max_response_bytes:
                raise RFC3161FetchError(f"Response size exceeds limit of {max_response_bytes} bytes.")

            if not body:
                raise RFC3161FetchError("TSA server returned an empty response.")

            return RFC3161Response(
                response_bytes=body,
                tsa_url=tsa_url,
                status_code=status_code,
                content_type=content_type,
            )

    except urllib.error.HTTPError as e:
        raise RFC3161FetchError(f"HTTP error from TSA server: {e.code} {e.reason}") from e
    except urllib.error.URLError as e:
        raise RFC3161FetchError(f"Network failure connecting to TSA: {e.reason}") from e
    except Exception as e:
        if isinstance(e, RFC3161FetchError):
            raise
        raise RFC3161FetchError(f"Failed to fetch timestamp response: {str(e)}") from e
