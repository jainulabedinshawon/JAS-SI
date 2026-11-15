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

    def test_agent_task_submission_uses_its_write_scope(self):
        from unittest.mock import MagicMock, patch
        from datetime import datetime, timezone

        connection = MagicMock()
        cursor = MagicMock()
        connection.__enter__.return_value = connection
        connection.cursor.return_value.__enter__.return_value = cursor
        cursor.fetchone.return_value = (
            "00000000-0000-0000-0000-000000000033",
            "agent.task.submit", 1, datetime(2026, 11, 15, tzinfo=timezone.utc),
            False, 100, 1, 99, datetime(2026, 11, 1, tzinfo=timezone.utc),
            datetime(2026, 12, 1, tzinfo=timezone.utc),
        )
        with patch("psycopg.connect", return_value=connection) as connect:
            result = self.meter.record_authenticated(
                **{
                    **self.common,
                    "required_scope": "agent:tasks:write",
                    "operation": "agent.task.submit",
                },
            )
        self.assertEqual(result["operation"], "agent.task.submit")
        self.assertFalse(result["replayed"])
        connect.assert_called_once_with("postgresql://unused")

    def test_agent_task_submission_rejects_read_scope(self):
        with self.assertRaises(ValueError):
            self.meter.record_authenticated(
                **{
                    **self.common,
                    "required_scope": "agent:tasks:read",
                    "operation": "agent.task.submit",
                },
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
