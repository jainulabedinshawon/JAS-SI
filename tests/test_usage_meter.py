"""Tests for authenticated usage metering validation contracts."""
from datetime import datetime, timezone
from unittest import TestCase

from jas_si_agent.usage_meter import PostgresUsageMeter


class UsageMeterValidationTests(TestCase):
    def setUp(self):
        self.meter = PostgresUsageMeter("postgresql://unused")
        self.common = {
            "api_key_id": "00000000-0000-0000-0000-000000000002",
            "candidate_digest": b"x" * 32,
            "required_scope": "authorization:check",
            "request_id": "req",
            "idempotency_key": "idem",
            "request_fingerprint": "0" * 64,
            "monthly_limit": 100,
        }

    def test_rejects_unknown_operation_before_database_access(self):
        with self.assertRaises(ValueError):
            self.meter.record_authenticated(
                **self.common, operation="customer.supplied.operation",
            )

    def test_rejects_non_unit_client_controlled_quantity(self):
        with self.assertRaises(ValueError):
            self.meter.record_authenticated(
                **self.common, operation="authorization.evaluate", units=999,
            )

    def test_rejects_invalid_api_key_context(self):
        with self.assertRaises(ValueError):
            self.meter.summary_authenticated(
                api_key_id="not-a-uuid",
                candidate_digest=b"x" * 32,
                since=datetime.now(timezone.utc),
                tenant_id_for_response="00000000-0000-0000-0000-000000000001",
            )

    def test_utc_month_window_handles_year_boundary(self):
        from jas_si_agent.usage_meter import _utc_month_window
        start, end = _utc_month_window(datetime(2026, 12, 10, 12, tzinfo=timezone.utc))
        self.assertEqual(start, datetime(2026, 12, 1, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2027, 1, 1, tzinfo=timezone.utc))
