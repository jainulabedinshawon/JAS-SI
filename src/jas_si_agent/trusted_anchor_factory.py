from __future__ import annotations

from jas_si_agent.config import Settings
from jas_si_agent.trusted_anchor_hmac_adapter import (
    HmacVerifyingTrustedAnchorProvider,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorProvider,
    TrustedAnchorProviderError,
)


def create_trusted_anchor_provider(
    settings: Settings,
    backend: TrustedAnchorProvider,
) -> HmacVerifyingTrustedAnchorProvider:
    """Build an HMAC-verifying provider from explicit settings.

    Fail closed when credentials or a valid backend are unavailable.
    This factory does not create or connect to an external service.
    """

    if not isinstance(settings, Settings):
        raise TrustedAnchorProviderError(
            "A valid Settings instance is required"
        )

    secret = settings.trusted_anchor_hmac_secret
    provider_id = settings.trusted_anchor_provider_id

    if secret is None or provider_id is None:
        raise TrustedAnchorProviderError(
            "Trusted Anchor credentials are not configured"
        )

    if not isinstance(backend, TrustedAnchorProvider):
        raise TrustedAnchorProviderError(
            "A valid Trusted Anchor backend is required"
        )

    try:
        return HmacVerifyingTrustedAnchorProvider(
            backend,
            provider_id=provider_id,
            secret=secret,
        )
    except Exception as exc:
        raise TrustedAnchorProviderError(
            "Trusted Anchor provider initialization failed"
        ) from exc
