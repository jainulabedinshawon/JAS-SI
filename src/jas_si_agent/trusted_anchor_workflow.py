
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
    """Publish, verify, and persist an anchor with a local duplicate guard.

    A previously persisted anchor is rejected before contacting the provider.
    This is a local guard, not a distributed exactly-once guarantee.
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

    # Preflight: do not publish an anchor already present in the journal.
    try:
        existing_anchors = journal.load()
    except SecurityCheckpointAnchorJournalError as exc:
        raise TrustedAnchorWorkflowError(
            "Unable to inspect local anchor journal before publication"
        ) from exc

    if any(
        existing.digest == anchor.digest
        for existing in existing_anchors
    ):
        raise TrustedAnchorWorkflowError(
            "Anchor is already persisted; duplicate publication blocked"
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
