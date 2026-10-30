from __future__ import annotations

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.security_checkpoint_anchor_journal import (
    SecurityCheckpointAnchorJournal,
    SecurityCheckpointAnchorJournalError,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorProvider,
    TrustedAnchorProviderError,
    TrustedAnchorReceipt,
    publish_and_verify_anchor,
)


class TrustedAnchorWorkflowError(RuntimeError):
    """Raised when verified publication and persistence cannot complete."""


def publish_verify_and_persist_anchor(
    provider: TrustedAnchorProvider,
    journal: SecurityCheckpointAnchorJournal,
    anchor: SecurityCheckpointAnchor,
) -> TrustedAnchorReceipt:
    """Verify an externally published anchor before local persistence.

    The journal is updated only after provider verification succeeds.
    A journal failure is reported explicitly; it does not undo an
    already completed external publication.
    """

    if not isinstance(anchor, SecurityCheckpointAnchor):
        raise TrustedAnchorWorkflowError(
            "A valid SecurityCheckpointAnchor is required"
        )

    if not isinstance(provider, TrustedAnchorProvider):
        raise TrustedAnchorWorkflowError(
            "A valid Trusted Anchor provider is required"
        )

    if not isinstance(journal, SecurityCheckpointAnchorJournal):
        raise TrustedAnchorWorkflowError(
            "A valid SecurityCheckpointAnchorJournal is required"
        )

    try:
        receipt = publish_and_verify_anchor(provider, anchor)
    except TrustedAnchorProviderError as exc:
        raise TrustedAnchorWorkflowError(
            "Trusted Anchor publication or verification failed"
        ) from exc

    try:
        journal.append(anchor)
    except SecurityCheckpointAnchorJournalError as exc:
        raise TrustedAnchorWorkflowError(
            "Anchor was externally verified but local persistence failed"
        ) from exc

    return receipt
