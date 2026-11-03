
from __future__ import annotations

import math
import urllib.error
import urllib.request

from dataclasses import dataclass
from urllib.parse import urlsplit

from jas_si_agent.rfc3161_request import RFC3161TimestampRequest


DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_RESPONSE_BYTES = 65536


class RFC3161FetchError(Exception):
    """Raised when timestamp response acquisition fails."""


@dataclass(frozen=True)
class RFC3161Response:
    response_bytes: bytes
    tsa_url: str
    status_code: int
    content_type: str


def fetch_timestamp_response(
    request: RFC3161TimestampRequest,
    tsa_url: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> RFC3161Response:
    """
    Submit an RFC 3161 timestamp request to a TSA endpoint.

    The original request DER bytes are transmitted unchanged.
    Response size is bounded before returning the response.
    """

    if not isinstance(request, RFC3161TimestampRequest):
        raise RFC3161FetchError(
            "A valid RFC3161TimestampRequest object is required."
        )

    if (
        not isinstance(request.request_bytes, bytes)
        or not request.request_bytes
    ):
        raise RFC3161FetchError(
            "Timestamp request bytes must be non-empty bytes."
        )

    if not isinstance(tsa_url, str):
        raise RFC3161FetchError("TSA URL must be a string.")

    try:
        parsed_url = urlsplit(tsa_url)
        valid_url = (
            parsed_url.scheme in ("http", "https")
            and bool(parsed_url.hostname)
            and parsed_url.username is None
            and parsed_url.password is None
            and not parsed_url.fragment
        )
    except ValueError:
        valid_url = False

    if not valid_url:
        raise RFC3161FetchError(
            "Invalid TSA URL. A valid HTTP or HTTPS URL without credentials or fragments is required."
        )

    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise RFC3161FetchError(
            "Timeout must be a positive finite number."
        )

    if (
        not isinstance(max_response_bytes, int)
        or isinstance(max_response_bytes, bool)
        or not 1 <= max_response_bytes <= 1048576
    ):
        raise RFC3161FetchError(
            "Maximum response size must be between 1 and 1048576 bytes."
        )

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
        with urllib.request.urlopen(
            req,
            timeout=timeout,
        ) as resp:

            status_code = resp.getcode()
            content_type = resp.headers.get("Content-Type", "")

            if status_code != 200:
                raise RFC3161FetchError(
                    f"TSA server returned unexpected HTTP status: {status_code}"
                )

            body = resp.read(max_response_bytes + 1)

            if len(body) > max_response_bytes:
                raise RFC3161FetchError(
                    "TSA response exceeded the configured size limit."
                )

            if not body:
                raise RFC3161FetchError(
                    "TSA server returned an empty response."
                )

            return RFC3161Response(
                response_bytes=body,
                tsa_url=tsa_url,
                status_code=status_code,
                content_type=content_type,
            )

    except urllib.error.HTTPError as exc:
        raise RFC3161FetchError(
            f"HTTP error from TSA server: {exc.code} {exc.reason}"
        ) from exc

    except urllib.error.URLError as exc:
        raise RFC3161FetchError(
            f"Network failure connecting to TSA: {exc.reason}"
        ) from exc

    except RFC3161FetchError:
        raise

    except (OSError, TimeoutError) as exc:
        raise RFC3161FetchError(
            "Network operation failed while fetching timestamp response."
        ) from exc

    except Exception as exc:
        raise RFC3161FetchError(
            "Unexpected failure while fetching timestamp response."
        ) from exc
