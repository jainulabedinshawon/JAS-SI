"""Storage contract for JAS-SI security audit events.

Backends must provide durable append semantics:
append() must return only after the event has been
successfully persisted.

A backend must raise an exception when persistence fails.
Callers must never interpret a failed write as success.
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol


class SecurityEventStore(Protocol):
    """Backend-independent contract for security event storage."""

    def append(self, event: Mapping[str, Any]) -> None:
        """Persist one security event.

        Args:
            event: Sanitized JSON-compatible security event.

        Raises:
            Exception: If the event cannot be durably persisted.
        """
        ...
