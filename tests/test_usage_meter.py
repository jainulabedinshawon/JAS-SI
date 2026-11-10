"""Tests for usage metering validation and tenant-safe query contracts."""
from datetime import datetime, timezone
from unittest import TestCase
from unittest.mock import patch

from jas_si_agent.usage_meter import PostgresUsageMeter


class UsageMeterValidationTests(TestCase):
    def test_rejects_unknown_operation_before_database_access(self):
        meter = PostgresUsageMeter("postgresql://unused")
        with self.assertRaises(ValueError):
            meter.record(
                tenant_id="00000000-0000-0000-0000-000000000001",
                api_key_id="00000000-0000-0000-0000-000000000002",
                request_id="req", idempotency_key="idem",
                operation="customer.supplied.operation", request_fingerprint="0" * 64,
                monthly_limit=100,
            )

    def test_rejects_non_unit_client_controlled_quantity(self):
        meter = PostgresUsageMeter("postgresql://unused")
        with self.assertRaises(ValueError):
            meter.record(
                tenant_id="00000000-0000-0000-0000-000000000001",
                api_key_id="00000000-0000-0000-0000-000000000002",
                request_id="req", idempotency_key="idem",
                operation="authorization.evaluate", units=999,
                request_fingerprint="0" * 64, monthly_limit=100,
            )

    def test_rejects_invalid_tenant_context(self):
        meter = PostgresUsageMeter("postgresql://unused")
        with self.assertRaises(ValueError):
            meter.summary(tenant_id="not-a-uuid", since=datetime.now(timezone.utc))

    def test_utc_month_window_handles_year_boundary(self):
        from jas_si_agent.usage_meter import _utc_month_window
        start, end = _utc_month_window(datetime(2026, 12, 10, 12, tzinfo=timezone.utc))
        self.assertEqual(start, datetime(2026, 12, 1, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2027, 1, 1, tzinfo=timezone.utc))
