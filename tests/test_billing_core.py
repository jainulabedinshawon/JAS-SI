from __future__ import annotations

import sys
import unittest
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.billing_core import (  # noqa: E402
    BillingInvariantError,
    BillingOrder,
    CreditBalance,
    IdempotencyConflict,
    InMemoryCreditLedger,
    Money,
    OrderStatus,
    VerifiedPayment,
    apply_verified_payment,
)


class TestBillingMoneyAndOrders(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant_id = uuid4()
        self.order = BillingOrder(
            order_id=uuid4(),
            tenant_id=self.tenant_id,
            amount=Money(1250, "USD"),
            credit_quantity=500,
        )

    def test_money_uses_integer_minor_units(self) -> None:
        with self.assertRaises(BillingInvariantError):
            Money(12.5, "USD")  # type: ignore[arg-type]
        with self.assertRaises(BillingInvariantError):
            Money(True, "USD")
        with self.assertRaises(BillingInvariantError):
            Money(-1, "USD")

    def test_currency_must_be_uppercase_three_letter_code(self) -> None:
        with self.assertRaises(BillingInvariantError):
            Money(100, "usd")
        with self.assertRaises(BillingInvariantError):
            Money(100, "US")

    def test_order_state_machine_rejects_skipping_payment_pending(self) -> None:
        with self.assertRaises(BillingInvariantError):
            self.order.transition(OrderStatus.PAID)

    def test_verified_payment_must_match_order_reference_amount_and_currency(
        self,
    ) -> None:
        pending = self.order.transition(OrderStatus.PENDING_PAYMENT)
        payment = VerifiedPayment(
            provider="sandbox",
            provider_account_id="merchant-test",
            provider_event_id="evt-001",
            provider_transaction_id="txn-001",
            order_id=pending.order_id,
            amount=Money(1250, "USD"),
        )
        self.assertEqual(
            apply_verified_payment(pending, payment).status,
            OrderStatus.PAID,
        )

        wrong_amount = VerifiedPayment(
            provider="sandbox",
            provider_account_id="merchant-test",
            provider_event_id="evt-002",
            provider_transaction_id="txn-002",
            order_id=pending.order_id,
            amount=Money(1249, "USD"),
        )
        with self.assertRaises(BillingInvariantError):
            apply_verified_payment(pending, wrong_amount)

        wrong_order = VerifiedPayment(
            provider="sandbox",
            provider_account_id="merchant-test",
            provider_event_id="evt-003",
            provider_transaction_id="txn-003",
            order_id=uuid4(),
            amount=Money(1250, "USD"),
        )
        with self.assertRaises(BillingInvariantError):
            apply_verified_payment(pending, wrong_order)


class TestInMemoryCreditLedger(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant_id = uuid4()
        self.other_tenant_id = uuid4()
        self.ledger = InMemoryCreditLedger()

    def test_grant_reserve_capture_and_release_reconcile(self) -> None:
        self.ledger.grant(
            self.tenant_id, 1000,
            idempotency_key="purchase-1",
            source_reference="order-1",
        )
        self.ledger.reserve(
            self.tenant_id, 300,
            idempotency_key="usage-reserve-1",
            source_reference="usage-1",
        )
        self.assertEqual(
            self.ledger.balance(self.tenant_id),
            CreditBalance(available=700, reserved=300),
        )
        self.ledger.capture(
            self.tenant_id, 200,
            idempotency_key="usage-capture-1",
            source_reference="usage-1",
        )
        self.ledger.release(
            self.tenant_id, 100,
            idempotency_key="usage-release-1",
            source_reference="usage-1",
        )
        self.assertEqual(
            self.ledger.balance(self.tenant_id),
            CreditBalance(available=800, reserved=0),
        )

    def test_insufficient_available_credits_are_denied(self) -> None:
        with self.assertRaises(BillingInvariantError):
            self.ledger.reserve(
                self.tenant_id, 1,
                idempotency_key="reserve-too-much",
                source_reference="usage-x",
            )
        self.assertEqual(
            self.ledger.balance(self.tenant_id),
            CreditBalance(available=0, reserved=0),
        )

    def test_capture_cannot_exceed_reserved_balance(self) -> None:
        self.ledger.grant(
            self.tenant_id, 10,
            idempotency_key="grant",
            source_reference="order",
        )
        self.ledger.reserve(
            self.tenant_id, 4,
            idempotency_key="reserve",
            source_reference="usage",
        )
        with self.assertRaises(BillingInvariantError):
            self.ledger.capture(
                self.tenant_id, 5,
                idempotency_key="capture-too-much",
                source_reference="usage",
            )

    def test_capture_must_match_its_own_reservation_source(self) -> None:
        self.ledger.grant(
            self.tenant_id, 10,
            idempotency_key="grant-source",
            source_reference="order",
        )
        self.ledger.reserve(
            self.tenant_id, 4,
            idempotency_key="reserve-source-a",
            source_reference="usage-a",
        )
        self.ledger.reserve(
            self.tenant_id, 4,
            idempotency_key="reserve-source-b",
            source_reference="usage-b",
        )
        with self.assertRaises(BillingInvariantError):
            self.ledger.capture(
                self.tenant_id, 5,
                idempotency_key="capture-wrong-source",
                source_reference="usage-a",
            )
        self.assertEqual(
            self.ledger.balance(self.tenant_id),
            CreditBalance(available=2, reserved=8),
        )

    def test_duplicate_idempotent_operation_does_not_duplicate_credits(
        self,
    ) -> None:
        first = self.ledger.grant(
            self.tenant_id, 100,
            idempotency_key="same-event",
            source_reference="order-1",
        )
        second = self.ledger.grant(
            self.tenant_id, 100,
            idempotency_key="same-event",
            source_reference="order-1",
        )
        self.assertEqual(first, second)
        self.assertEqual(len(self.ledger.entries), 1)
        self.assertEqual(self.ledger.balance(self.tenant_id).available, 100)

    def test_reusing_idempotency_key_for_different_operation_is_rejected(
        self,
    ) -> None:
        self.ledger.grant(
            self.tenant_id, 100,
            idempotency_key="same-event",
            source_reference="order-1",
        )
        with self.assertRaises(IdempotencyConflict):
            self.ledger.grant(
                self.tenant_id, 200,
                idempotency_key="same-event",
                source_reference="order-1",
            )

    def test_tenant_balances_are_isolated(self) -> None:
        self.ledger.grant(
            self.tenant_id, 100,
            idempotency_key="tenant-a",
            source_reference="order-a",
        )
        self.ledger.grant(
            self.other_tenant_id, 900,
            idempotency_key="tenant-b",
            source_reference="order-b",
        )
        self.assertEqual(self.ledger.balance(self.tenant_id).available, 100)
        self.assertEqual(
            self.ledger.balance(self.other_tenant_id).available, 900
        )

    def test_ledger_entries_are_exposed_as_immutable_snapshot(self) -> None:
        self.ledger.grant(
            self.tenant_id, 10,
            idempotency_key="grant",
            source_reference="order",
        )
        snapshot = self.ledger.entries
        self.assertIsInstance(snapshot, tuple)
        self.assertEqual(len(snapshot), 1)

    def test_reversal_must_match_original_grant_and_cannot_exceed_it(self) -> None:
        self.ledger.grant(
            self.tenant_id, 100,
            idempotency_key="grant-reversal",
            source_reference="order-reversal",
        )
        self.ledger.reverse(
            self.tenant_id, 60,
            idempotency_key="reverse-partial",
            source_reference="order-reversal",
        )
        with self.assertRaises(BillingInvariantError):
            self.ledger.reverse(
                self.tenant_id, 41,
                idempotency_key="reverse-excess",
                source_reference="order-reversal",
            )
        with self.assertRaises(BillingInvariantError):
            self.ledger.reverse(
                self.tenant_id, 1,
                idempotency_key="reverse-unknown-source",
                source_reference="not-a-grant",
            )
        self.assertEqual(
            self.ledger.balance(self.tenant_id),
            CreditBalance(available=40, reserved=0),
        )


if __name__ == "__main__":
    unittest.main()
