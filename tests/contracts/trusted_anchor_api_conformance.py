
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Protocol

from jas_si_agent.security_checkpoint_anchor import (
    SecurityCheckpointAnchor,
)
from jas_si_agent.trusted_anchor_provider import (
    TrustedAnchorReceipt,
)


class TrustedAnchorConformanceBackend(Protocol):
    """Backend interface required by the provider conformance suite."""

    def publish_idempotent(
        self,
        anchor: SecurityCheckpointAnchor,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt:
        ...

    def lookup_by_idempotency_key(
        self,
        idempotency_key: str,
    ) -> TrustedAnchorReceipt | None:
        ...


@dataclass(frozen=True)
class ConformanceResult:
    name: str
    passed: bool
    detail: str


class TrustedAnchorProviderConformance:
    """Reusable behavioral checks for an idempotent anchor provider.

    These checks establish observed behavior in the test environment.
    They do not prove production guarantees or provider-wide reliability.
    """

    def __init__(
        self,
        backend: TrustedAnchorConformanceBackend,
    ) -> None:
        self.backend = backend

    def _check(
        self,
        name: str,
        operation: Callable[[], None],
    ) -> ConformanceResult:
        try:
            operation()
        except Exception as exc:
            return ConformanceResult(
                name=name,
                passed=False,
                detail=f"{type(exc).__name__}: {exc}",
            )

        return ConformanceResult(
            name=name,
            passed=True,
            detail="passed",
        )

    def check_publish_and_lookup(
        self,
        anchor: SecurityCheckpointAnchor,
    ) -> ConformanceResult:
        def operation() -> None:
            receipt = self.backend.publish_idempotent(
                anchor,
                anchor.digest,
            )

            if not isinstance(receipt, TrustedAnchorReceipt):
                raise AssertionError("Invalid publication receipt")

            if receipt.anchor_digest != anchor.digest:
                raise AssertionError("Receipt digest mismatch")

            recovered = self.backend.lookup_by_idempotency_key(
                anchor.digest,
            )

            if recovered != receipt:
                raise AssertionError(
                    "Lookup did not return published receipt"
                )

        return self._check("publish_and_lookup", operation)

    def check_idempotent_replay(
        self,
        anchor: SecurityCheckpointAnchor,
    ) -> ConformanceResult:
        def operation() -> None:
            first = self.backend.publish_idempotent(
                anchor,
                anchor.digest,
            )

            second = self.backend.publish_idempotent(
                anchor,
                anchor.digest,
            )

            if not isinstance(first, TrustedAnchorReceipt):
                raise AssertionError("Invalid first receipt")

            if not isinstance(second, TrustedAnchorReceipt):
                raise AssertionError("Invalid replay receipt")

            if first != second:
                raise AssertionError(
                    "Replay returned a different receipt"
                )

        return self._check("idempotent_replay", operation)

    def check_concurrent_replay(
        self,
        anchor: SecurityCheckpointAnchor,
        *,
        workers: int = 8,
    ) -> ConformanceResult:
        def operation() -> None:
            if (
                not isinstance(workers, int)
                or isinstance(workers, bool)
                or workers < 2
                or workers > 32
            ):
                raise ValueError(
                    "workers must be an integer between 2 and 32"
                )

            def publish_once() -> TrustedAnchorReceipt:
                return self.backend.publish_idempotent(
                    anchor,
                    anchor.digest,
                )

            with ThreadPoolExecutor(
                max_workers=workers,
            ) as executor:
                receipts = list(
                    executor.map(
                        lambda _: publish_once(),
                        range(workers),
                    )
                )

            if not receipts:
                raise AssertionError(
                    "No publication receipts returned"
                )

            first = receipts[0]

            if not isinstance(first, TrustedAnchorReceipt):
                raise AssertionError("Invalid concurrent receipt")

            if first.anchor_digest != anchor.digest:
                raise AssertionError(
                    "Concurrent receipt digest mismatch"
                )

            if any(
                not isinstance(receipt, TrustedAnchorReceipt)
                or receipt != first
                for receipt in receipts[1:]
            ):
                raise AssertionError(
                    "Concurrent replay returned inconsistent receipts"
                )

            recovered = self.backend.lookup_by_idempotency_key(
                anchor.digest,
            )

            if recovered != first:
                raise AssertionError(
                    "Lookup differs from concurrent publication receipt"
                )

        return self._check("concurrent_replay", operation)

    def check_idempotency_key_conflict(
        self,
        anchor: SecurityCheckpointAnchor,
        conflicting_anchor: SecurityCheckpointAnchor,
    ) -> ConformanceResult:
        def operation() -> None:
            if anchor.digest == conflicting_anchor.digest:
                raise ValueError(
                    "Conflict test requires different anchor digests"
                )

            original_receipt = self.backend.publish_idempotent(
                anchor,
                anchor.digest,
            )

            if not isinstance(original_receipt, TrustedAnchorReceipt):
                raise AssertionError("Invalid original receipt")

            if original_receipt.anchor_digest != anchor.digest:
                raise AssertionError("Original receipt digest mismatch")

            try:
                self.backend.publish_idempotent(
                    conflicting_anchor,
                    anchor.digest,
                )
            except Exception:
                pass
            else:
                raise AssertionError(
                    "Backend did not reject an idempotency key conflict"
                )

            recovered = self.backend.lookup_by_idempotency_key(
                anchor.digest,
            )

            if recovered != original_receipt:
                raise AssertionError(
                    "Conflict changed the original receipt"
                )

            conflicting_record = self.backend.lookup_by_idempotency_key(
                conflicting_anchor.digest,
            )

            if conflicting_record is not None:
                raise AssertionError(
                    "Conflict created an unexpected second record"
                )

        return self._check("idempotency_key_conflict", operation)

    def check_wrong_idempotency_key(
        self,
        anchor: SecurityCheckpointAnchor,
    ) -> ConformanceResult:
        def operation() -> None:
            wrong_key = "0" * 64

            if wrong_key == anchor.digest:
                raise ValueError(
                    "Test requires a different idempotency key"
                )

            # Preserve existing state because earlier checks in run()
            # may already have published this anchor.
            original_record = (
                self.backend.lookup_by_idempotency_key(
                    anchor.digest,
                )
            )

            wrong_record_before = (
                self.backend.lookup_by_idempotency_key(
                    wrong_key,
                )
            )

            # An incorrect key must be rejected.
            try:
                self.backend.publish_idempotent(
                    anchor,
                    wrong_key,
                )
            except Exception:
                pass
            else:
                raise AssertionError(
                    "Backend accepted an incorrect idempotency key"
                )

            # The original record must remain unchanged.
            existing_after = (
                self.backend.lookup_by_idempotency_key(
                    anchor.digest,
                )
            )

            if existing_after != original_record:
                raise AssertionError(
                    "Wrong key changed the original publication"
                )

            # The wrong-key record must also remain unchanged.
            wrong_record_after = (
                self.backend.lookup_by_idempotency_key(
                    wrong_key,
                )
            )

            if wrong_record_after != wrong_record_before:
                raise AssertionError(
                    "Wrong key created or changed a publication"
                )

        return self._check(
            "wrong_idempotency_key",
            operation,
        )

    def check_missing_lookup(
        self,
        missing_key: str,
    ) -> ConformanceResult:
        def operation() -> None:
            result = self.backend.lookup_by_idempotency_key(
                missing_key,
            )

            if result is not None:
                raise AssertionError(
                    "Missing key unexpectedly returned a receipt"
                )

        return self._check("missing_lookup", operation)

    def run(
        self,
        anchor: SecurityCheckpointAnchor,
        *,
        missing_key: str,
        conflicting_anchor: SecurityCheckpointAnchor,
    ) -> tuple[ConformanceResult, ...]:
        return (
            self.check_publish_and_lookup(anchor),
            self.check_idempotent_replay(anchor),
            self.check_concurrent_replay(anchor),
            self.check_idempotency_key_conflict(
                anchor,
                conflicting_anchor,
            ),
            self.check_wrong_idempotency_key(anchor),
            self.check_missing_lookup(missing_key),
        )
