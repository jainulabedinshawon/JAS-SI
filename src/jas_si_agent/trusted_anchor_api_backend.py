from __future__ import annotations

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_api_client import (
    TrustedAnchorApiClient,
    TrustedAnchorApiClientError,
)
from jas_si_agent.trusted_anchor_api_recovery import (
    TrustedAnchorApiRecoveryError,
    TrustedAnchorApiRecoveryBackend,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)


class TrustedAnchorApiBackendAdapter:
    """Adapt the authenticated API client to the recovery backend contract.

    Provider-side atomic idempotency and lookup consistency must be
    guaranteed by the actual remote provider, not by this adapter.
    """

    def __init__(
        self,
        client: TrustedAnchorApiClient,
    ) -> None:
        if not isinstance(client, TrustedAnchorApiClient):
            raise TrustedAnchorApiRecoveryError(
                "A valid TrustedAnchorApiClient is required"
            )

        self._client = client

    def publish_idempotent(
        self,
        anchor: SecurityCheckpointAnchor,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt:
        if not isinstance(anchor, SecurityCheckpointAnchor):
            raise TrustedAnchorApiRecoveryError(
                "A valid checkpoint anchor is required"
            )

        if idempotency_key != anchor.digest:
            raise TrustedAnchorApiRecoveryError(
                "Idempotency key must equal the anchor digest"
            )

        try:
            return self._client.publish(
                anchor,
                idempotency_key=idempotency_key,
            )
        except TrustedAnchorApiClientError as exc:
            raise TrustedAnchorApiRecoveryError(
                "API backend publication failed"
            ) from exc

    def lookup_by_idempotency_key(
        self,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt | None:
        try:
            return self._client.lookup_by_idempotency_key(
                idempotency_key
            )
        except TrustedAnchorApiClientError as exc:
            raise TrustedAnchorApiRecoveryError(
                "API backend receipt lookup failed"
            ) from exc
