"""Fail-closed GitHub App webhook authentication and event normalization.

This module authenticates the exact raw request body before JSON parsing. It
never derives a tenant identity from webhook payload data. Durable delivery
deduplication and reconciliation belong to the persistence/application layer.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

_SIGNATURE_RE = re.compile(r"^sha256=[0-9a-f]{64}$")
_DELIVERY_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
_SUPPORTED_EVENTS = {
    "installation": {
        "created",
        "deleted",
        "suspend",
        "unsuspend",
        "new_permissions_accepted",
    },
    "installation_repositories": {"added", "removed"},
}


class GitHubWebhookError(ValueError):
    """A webhook request cannot be safely authenticated or interpreted."""


@dataclass(frozen=True)
class VerifiedGitHubWebhook:
    delivery_id: str
    event_name: str
    action: str
    installation_id: int
    payload: Mapping[str, Any]


def verify_github_webhook_signature(
    *, secret: str | bytes, raw_body: bytes, signature_header: str
) -> None:
    """Raise unless X-Hub-Signature-256 matches the exact raw request bytes."""
    if isinstance(secret, str):
        secret_bytes = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        secret_bytes = secret
    else:
        raise GitHubWebhookError("Webhook secret is invalid")
    if not secret_bytes or len(secret_bytes) > 4096:
        raise GitHubWebhookError("Webhook secret is invalid")
    if not isinstance(raw_body, bytes) or len(raw_body) > 2_000_000:
        raise GitHubWebhookError("Webhook body is invalid")
    if not isinstance(signature_header, str) or not _SIGNATURE_RE.fullmatch(
        signature_header
    ):
        raise GitHubWebhookError("Webhook signature is invalid")

    expected = "sha256=" + hmac.new(
        secret_bytes, raw_body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature_header):
        raise GitHubWebhookError("Webhook signature verification failed")


def parse_verified_github_webhook(
    *,
    delivery_id: str,
    event_name: str,
    raw_body: bytes,
) -> VerifiedGitHubWebhook:
    """Parse an already-authenticated event; never infer a tenant from it."""
    if not isinstance(delivery_id, str) or not _DELIVERY_RE.fullmatch(delivery_id):
        raise GitHubWebhookError("GitHub delivery ID is invalid")
    if event_name not in _SUPPORTED_EVENTS:
        raise GitHubWebhookError("GitHub webhook event is unsupported")
    if not isinstance(raw_body, bytes) or len(raw_body) > 2_000_000:
        raise GitHubWebhookError("GitHub webhook body is invalid")
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GitHubWebhookError("GitHub webhook JSON is invalid") from None
    if not isinstance(payload, dict):
        raise GitHubWebhookError("GitHub webhook payload must be an object")

    action = payload.get("action")
    if not isinstance(action, str) or action not in _SUPPORTED_EVENTS[event_name]:
        raise GitHubWebhookError("GitHub webhook action is unsupported")
    installation = payload.get("installation")
    if not isinstance(installation, dict):
        raise GitHubWebhookError("GitHub installation data is missing")
    installation_id = installation.get("id")
    if (
        isinstance(installation_id, bool)
        or not isinstance(installation_id, int)
        or installation_id <= 0
    ):
        raise GitHubWebhookError("GitHub installation ID is invalid")

    # A payload is only a signal to reconcile against GitHub's API. Fields
    # such as account, repository list, sender, and tenant are not trusted as
    # authoritative ownership or allowlist state.
    return VerifiedGitHubWebhook(
        delivery_id=delivery_id,
        event_name=event_name,
        action=action,
        installation_id=installation_id,
        payload=payload,
    )
