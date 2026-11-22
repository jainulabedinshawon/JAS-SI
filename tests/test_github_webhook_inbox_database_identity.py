"""Tests for the isolated GitHub webhook database login boundary."""
import sys
import types
import unittest
from unittest.mock import patch

from jas_si_agent.github_webhook_inbox import (
    GitHubWebhookInboxError,
    PostgresGitHubWebhookInbox,
)


class _FakeCursor:
    def __init__(self, session_user="jas_si_github_webhook_login"):
        self.statements = []
        self.params = []
        self.session_user = session_user
        self._row = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, statement, params=None):
        self.statements.append(statement)
        self.params.append(params)
        if statement == "SELECT session_user":
            self._row = (self.session_user,)
        elif "jas_si_github_webhook_receive" in statement:
            self._row = ("delivery-1", "RECEIVED", 0, True)

    def fetchone(self):
        return self._row


class _FakeConnection:
    def __init__(self, session_user="jas_si_github_webhook_login"):
        self.cursor_instance = _FakeCursor(session_user)
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return self.cursor_instance

    def close(self):
        self.closed = True


class GitHubWebhookInboxDatabaseIdentityTests(unittest.TestCase):
    def _patch_psycopg(self, connection):
        fake_psycopg = types.ModuleType("psycopg")
        fake_psycopg.connect = lambda *_args, **_kwargs: connection
        fake_json_module = types.ModuleType("psycopg.types.json")
        fake_json_module.Jsonb = lambda value: value
        fake_types_module = types.ModuleType("psycopg.types")
        fake_types_module.json = fake_json_module
        return patch.dict(sys.modules, {
            "psycopg": fake_psycopg,
            "psycopg.types": fake_types_module,
            "psycopg.types.json": fake_json_module,
        })

    def test_uses_dedicated_login_and_receipt_grant_without_setting_role(self):
        connection = _FakeConnection()
        with self._patch_psycopg(connection):
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
        statements = connection.cursor_instance.statements
        self.assertEqual(statements[0], "SELECT session_user")
        self.assertIn("jas_si_github_webhook_receive", statements[1])
        self.assertFalse(any("SET ROLE" in statement.upper() for statement in statements))

    def test_rejects_broad_or_unexpected_database_identity(self):
        connection = _FakeConnection(session_user="jas_si_runtime")
        with self._patch_psycopg(connection):
            with self.assertRaises(GitHubWebhookInboxError):
                PostgresGitHubWebhookInbox("postgresql://wrong-role").receive(
                    delivery_id="delivery-1",
                    event_name="installation",
                    action="created",
                    installation_id=123,
                    raw_body_sha256=b"x" * 32,
                    payload={"action": "created", "installation": {"id": 123}},
                )
        self.assertEqual(connection.cursor_instance.statements, ["SELECT session_user"])


if __name__ == "__main__":
    unittest.main()
