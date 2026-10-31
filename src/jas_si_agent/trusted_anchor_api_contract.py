
from __future__ import annotations

import re
from dataclasses import dataclass


class TrustedAnchorApiContractError(ValueError):
    """Invalid provider HTTP contract configuration."""


_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9._~-]+$")


@dataclass(frozen=True)
class TrustedAnchorApiContract:
    """Explicit provider HTTP contract; no provider defaults are assumed."""

    publish_path: str
    lookup_path_template: str
    idempotency_header: str
    success_status_codes: tuple[int, ...] = (200, 201)
    lookup_not_found_status_code: int = 404

    def __post_init__(self) -> None:
        self._validate_path(self.publish_path, "publish_path")

        if not isinstance(self.lookup_path_template, str):
            raise TrustedAnchorApiContractError(
                "Lookup path template must be a string"
            )

        if self.lookup_path_template.count("{idempotency_key}") != 1:
            raise TrustedAnchorApiContractError(
                "Lookup path must contain exactly one "
                "{idempotency_key} placeholder"
            )

        lookup_path = self.lookup_path_template.replace(
            "{idempotency_key}",
            "a" * 64,
        )
        self._validate_path(lookup_path, "lookup_path_template")

        if (
            not isinstance(self.idempotency_header, str)
            or not _HEADER_NAME.fullmatch(self.idempotency_header)
        ):
            raise TrustedAnchorApiContractError(
                "Invalid HTTP idempotency header name"
            )

        if (
            not isinstance(self.success_status_codes, tuple)
            or not self.success_status_codes
            or any(
                not isinstance(code, int)
                or isinstance(code, bool)
                or not 200 <= code <= 299
                for code in self.success_status_codes
            )
            or len(set(self.success_status_codes))
            != len(self.success_status_codes)
        ):
            raise TrustedAnchorApiContractError(
                "Success status codes must be unique HTTP 2xx integers"
            )

        if (
            not isinstance(self.lookup_not_found_status_code, int)
            or isinstance(self.lookup_not_found_status_code, bool)
            or not 400 <= self.lookup_not_found_status_code <= 499
            or self.lookup_not_found_status_code
            in self.success_status_codes
        ):
            raise TrustedAnchorApiContractError(
                "Lookup not-found status must be a distinct HTTP 4xx integer"
            )
    
    @staticmethod
    def _validate_path(path: str, field_name: str) -> None:
        if (
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or "://" in path
            or "\\" in path
            or "?" in path
            or "#" in path
            or any(
                not _PATH_SEGMENT.fullmatch(segment)
                or segment in {".", ".."}
                for segment in path.split("/")
            )
        ):
            raise TrustedAnchorApiContractError(
                f"Unsafe relative {field_name}"
            )

    def lookup_path(self, idempotency_key: str) -> str:
        if (
            not isinstance(idempotency_key, str)
            or len(idempotency_key) != 64
            or any(
                char not in "0123456789abcdef"
                for char in idempotency_key
            )
        ):
            raise TrustedAnchorApiContractError(
                "Idempotency key must be a lowercase SHA-256 digest"
            )

        return self.lookup_path_template.replace(
            "{idempotency_key}",
            idempotency_key,
        )
