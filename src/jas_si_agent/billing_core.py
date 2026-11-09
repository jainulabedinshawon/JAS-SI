"""Provider-neutral, in-memory Billing Core domain primitives.

This module deliberately contains no database, network, payment-provider,
or credential handling. It is a domain model/test foundation, not a
production ledger or payment-verification boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Dict, List, Tuple
from uuid import UUID


class BillingInvariantError(ValueError):
    """Raised when a billing operation violates a domain invariant."""


class IdempotencyConflict(BillingInvariantError):
    """Raised when an idempotency key is reused for a different operation."""


class OrderStatus(str, Enum):
    CREATED = "created"
    PENDING_PAYMENT = "pending_payment"
    PAID = "paid"
    PAYMENT_FAILED = "payment_failed"
    EXPIRED = "expired"
    PARTIALLY_REFUNDED = "partially_refunded"
    REFUNDED = "refunded"
    DISPUTED = "disputed"


_ALLOWED_TRANSITIONS = {
    OrderStatus.CREATED: {
        OrderStatus.PENDING_PAYMENT,
        OrderStatus.EXPIRED,
    },
    OrderStatus.PENDING_PAYMENT: {
        OrderStatus.PAID,
        OrderStatus.PAYMENT_FAILED,
        OrderStatus.EXPIRED,
    },
    OrderStatus.PAID: {
        OrderStatus.PARTIALLY_REFUNDED,
        OrderStatus.REFUNDED,
        OrderStatus.DISPUTED,
    },
    OrderStatus.PARTIALLY_REFUNDED: {
        OrderStatus.REFUNDED,
        OrderStatus.DISPUTED,
    },
    OrderStatus.PAYMENT_FAILED: set(),
    OrderStatus.EXPIRED: set(),
    OrderStatus.REFUNDED: set(),
    OrderStatus.DISPUTED: set(),
}


@dataclass(frozen=True)
class Money:
    """An exact monetary amount represented in currency minor units."""

    amount_minor: int
    currency: str

    def __post_init__(self) -> None:
        if isinstance(self.amount_minor, bool) or not isinstance(
            self.amount_minor, int
        ):
            raise BillingInvariantError("AMOUNT_MUST_BE_INTEGER_MINOR_UNITS")
        if self.amount_minor < 0:
            raise BillingInvariantError("AMOUNT_MUST_NOT_BE_NEGATIVE")
        if (
            not isinstance(self.currency, str)
            or len(self.currency) != 3
            or not self.currency.isascii()
            or not self.currency.isalpha()
            or self.currency.upper() != self.currency
        ):
            raise BillingInvariantError("CURRENCY_MUST_BE_UPPERCASE_ISO_CODE")


@dataclass(frozen=True)
class BillingOrder:
    """Immutable commercial snapshot; caller must derive tenant server-side."""

    order_id: UUID
    tenant_id: UUID
    amount: Money
    credit_quantity: int
    status: OrderStatus = OrderStatus.CREATED

    def __post_init__(self) -> None:
        if not isinstance(self.order_id, UUID) or not isinstance(
            self.tenant_id, UUID
        ):
            raise BillingInvariantError("ORDER_AND_TENANT_IDS_MUST_BE_UUIDS")
        if isinstance(self.credit_quantity, bool) or not isinstance(
            self.credit_quantity, int
        ):
            raise BillingInvariantError("CREDIT_QUANTITY_MUST_BE_INTEGER")
        if self.credit_quantity < 0:
            raise BillingInvariantError("CREDIT_QUANTITY_MUST_NOT_BE_NEGATIVE")
        if not isinstance(self.status, OrderStatus):
            raise BillingInvariantError("INVALID_ORDER_STATUS")

    def transition(self, target: OrderStatus) -> "BillingOrder":
        if not isinstance(target, OrderStatus):
            raise BillingInvariantError("INVALID_ORDER_STATUS")
        if target not in _ALLOWED_TRANSITIONS[self.status]:
            raise BillingInvariantError(
                f"INVALID_ORDER_TRANSITION:{self.status.value}:{target.value}"
            )
        return BillingOrder(
            order_id=self.order_id,
            tenant_id=self.tenant_id,
            amount=self.amount,
            credit_quantity=self.credit_quantity,
            status=target,
        )


@dataclass(frozen=True)
class VerifiedPayment:
    """Normalized payment data after provider-specific verification.

    Only trusted adapter code may construct/submit this command. This
    dataclass does not perform signature or provider verification itself.
    """

    provider: str
    provider_account_id: str
    provider_event_id: str
    provider_transaction_id: str
    order_id: UUID
    amount: Money


def apply_verified_payment(
    order: BillingOrder,
    payment: VerifiedPayment,
) -> BillingOrder:
    """Apply a previously verified payment only when it matches the order."""

    if not isinstance(order, BillingOrder) or not isinstance(
        payment, VerifiedPayment
    ):
        raise BillingInvariantError("INVALID_PAYMENT_CONFIRMATION")
    if not all(
        isinstance(value, str) and value.strip()
        for value in (
            payment.provider,
            payment.provider_account_id,
            payment.provider_event_id,
            payment.provider_transaction_id,
        )
    ):
        raise BillingInvariantError("INCOMPLETE_PROVIDER_PAYMENT_REFERENCE")
    if payment.order_id != order.order_id:
        raise BillingInvariantError("PAYMENT_ORDER_ID_MISMATCH")
    if payment.amount != order.amount:
        raise BillingInvariantError("PAYMENT_AMOUNT_OR_CURRENCY_MISMATCH")
    if order.status != OrderStatus.PENDING_PAYMENT:
        raise BillingInvariantError("ORDER_NOT_AWAITING_PAYMENT")
    return order.transition(OrderStatus.PAID)


class CreditEntryType(str, Enum):
    GRANT = "grant"
    RESERVE = "reserve"
    CAPTURE = "capture"
    RELEASE = "release"
    REVERSAL = "reversal"


@dataclass(frozen=True)
class CreditEntry:
    tenant_id: UUID
    entry_type: CreditEntryType
    quantity: int
    idempotency_key: str
    source_reference: str
    available_delta: int
    reserved_delta: int


@dataclass(frozen=True)
class CreditBalance:
    available: int
    reserved: int


class InMemoryCreditLedger:
    """Append-only in-memory ledger for deterministic domain tests only.

    Production must replace this with transactional PostgreSQL operations,
    row-level concurrency control, durable audit persistence and tenant
    authorization. This class is not durable or multi-process safe.
    """

    def __init__(self) -> None:
        self._entries: List[CreditEntry] = []
        self._idempotency: Dict[Tuple[UUID, str], CreditEntry] = {}
        self._lock = RLock()

    @property
    def entries(self) -> Tuple[CreditEntry, ...]:
        with self._lock:
            return tuple(self._entries)

    def balance(self, tenant_id: UUID) -> CreditBalance:
        if not isinstance(tenant_id, UUID):
            raise BillingInvariantError("INVALID_TENANT_ID")
        with self._lock:
            available = sum(
                item.available_delta
                for item in self._entries
                if item.tenant_id == tenant_id
            )
            reserved = sum(
                item.reserved_delta
                for item in self._entries
                if item.tenant_id == tenant_id
            )
            return CreditBalance(available=available, reserved=reserved)

    def _append(
        self,
        tenant_id: UUID,
        entry_type: CreditEntryType,
        quantity: int,
        idempotency_key: str,
        source_reference: str,
        available_delta: int,
        reserved_delta: int,
    ) -> CreditEntry:
        if not isinstance(tenant_id, UUID):
            raise BillingInvariantError("INVALID_TENANT_ID")
        if isinstance(quantity, bool) or not isinstance(quantity, int):
            raise BillingInvariantError("CREDIT_QUANTITY_MUST_BE_INTEGER")
        if quantity <= 0:
            raise BillingInvariantError("CREDIT_QUANTITY_MUST_BE_POSITIVE")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise BillingInvariantError("IDEMPOTENCY_KEY_REQUIRED")
        if not isinstance(source_reference, str) or not source_reference.strip():
            raise BillingInvariantError("SOURCE_REFERENCE_REQUIRED")

        key = (tenant_id, idempotency_key)
        candidate = CreditEntry(
            tenant_id=tenant_id,
            entry_type=entry_type,
            quantity=quantity,
            idempotency_key=idempotency_key,
            source_reference=source_reference,
            available_delta=available_delta,
            reserved_delta=reserved_delta,
        )
        with self._lock:
            previous = self._idempotency.get(key)
            if previous is not None:
                if previous != candidate:
                    raise IdempotencyConflict("IDEMPOTENCY_KEY_REUSED")
                return previous

            current = self.balance(tenant_id)
            next_available = current.available + available_delta
            next_reserved = current.reserved + reserved_delta
            if next_available < 0:
                raise BillingInvariantError("INSUFFICIENT_AVAILABLE_CREDITS")
            if next_reserved < 0:
                raise BillingInvariantError("INSUFFICIENT_RESERVED_CREDITS")

            self._entries.append(candidate)
            self._idempotency[key] = candidate
            return candidate

    def grant(
        self,
        tenant_id: UUID,
        quantity: int,
        *,
        idempotency_key: str,
        source_reference: str,
    ) -> CreditEntry:
        return self._append(
            tenant_id, CreditEntryType.GRANT, quantity, idempotency_key,
            source_reference, quantity, 0
        )

    def reserve(
        self,
        tenant_id: UUID,
        quantity: int,
        *,
        idempotency_key: str,
        source_reference: str,
    ) -> CreditEntry:
        return self._append(
            tenant_id, CreditEntryType.RESERVE, quantity, idempotency_key,
            source_reference, -quantity, quantity
        )

    def capture(
        self,
        tenant_id: UUID,
        quantity: int,
        *,
        idempotency_key: str,
        source_reference: str,
    ) -> CreditEntry:
        return self._append(
            tenant_id, CreditEntryType.CAPTURE, quantity, idempotency_key,
            source_reference, 0, -quantity
        )

    def release(
        self,
        tenant_id: UUID,
        quantity: int,
        *,
        idempotency_key: str,
        source_reference: str,
    ) -> CreditEntry:
        return self._append(
            tenant_id, CreditEntryType.RELEASE, quantity, idempotency_key,
            source_reference, quantity, -quantity
        )

    def reverse(
        self,
        tenant_id: UUID,
        quantity: int,
        *,
        idempotency_key: str,
        source_reference: str,
    ) -> CreditEntry:
        return self._append(
            tenant_id, CreditEntryType.REVERSAL, quantity, idempotency_key,
            source_reference, -quantity, 0
        )
