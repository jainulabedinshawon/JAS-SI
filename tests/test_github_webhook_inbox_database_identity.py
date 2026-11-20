"""Tests for the isolated GitHub webhook database login boundary."""
import sys
import types
import unittest
from unittest.mock import patch

from jas_si_agent.github_webhook_inbox import PostgresGitHubWebhookInbox


class _FakeCursor:
    def __init__(self):
        self.statements = []
        self.params = []
        self._row = ("delivery-1", "RECEIVED", 0, True)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, statement, params=None):
        self.statements.append(statement)
        self.params.append(params)

    def fetchone(self):
        return self._row


class _FakeConnection:
    def __init__(self):
        self.cursor_instance = _FakeCursor()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return self.cursor_instance


class GitHubWebhookInboxDatabaseIdentityTests(unittest.TestCase):
    def test_uses_direct_receipt_execute_grant_without_setting_runtime_role(self):
        connection = _FakeConnection()
        fake_psycopg = types.ModuleType("psycopg")
        fake_psycopg.connect = lambda *_args, **_kwargs: connection

        fake_json_module = types.ModuleType("psycopg.types.json")
        fake_json_module.Jsonb = lambda value: value
        fake_types_module = types.ModuleType("psycopg.types")
        fake_types_module.json = fake_json_module

        with patch.dict(sys.modules, {
            "psycopg": fake_psycopg,
            "psycopg.types": fake_types_module,
            "psycopg.types.json": fake_json_module,
        }):
            receipt = PostgresGitHubWebhookInbox("postgresql://dedicated-login").receive(
                delivery_id="delivery-1",
                event_name="installation",
                action="created",
                installation_id=123,
                raw_body_sha256=b"x" * 32,
                payload={"action": "created", "installation": {"id": 123}},
            )

        self.assertEqual(receipt.delivery_id, "delivery-1")
        self.assertTrue(receipt.inserted)
        self.assertEqual(len(connection.cursor_instance.statements), 1)
        self.assertIn(
            "jas_si_github_webhook_receive",
            connection.cursor_instance.statements[0],
        )
        self.assertFalse(any(
            "SET ROLE" in statement.upper()
            for statement in connection.cursor_instance.statements
        ))


if __name__ == "__main__":
    unittest.main()
