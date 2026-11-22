"""Database identity tests for the GitHub Installation reconciler."""
import sys
import types
import unittest
from unittest.mock import patch

from jas_si_agent.github_installation_reconciler import (
    PostgresGitHubInstallationReconciler,
)


class _Cursor:
    def __init__(self, session_user, current_user=None):
        self.session_user = session_user
        self.current_user = current_user
        self.statements = []
        self.row = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, statement, params=None):
        self.statements.append(statement)
        if statement == "SELECT session_user":
            self.row = (self.session_user,)
        elif statement == "SELECT current_user":
            self.row = (self.current_user,)

    def fetchone(self):
        return self.row


class _Connection:
    def __init__(self, session_user, current_user=None):
        self.cursor_instance = _Cursor(session_user, current_user)
        self.closed = False

    def cursor(self):
        return self.cursor_instance

    def close(self):
        self.closed = True


class _GitHub:
    pass


class GitHubReconcilerDatabaseIdentityTests(unittest.TestCase):
    def _patch_psycopg(self, connection):
        fake = types.ModuleType("psycopg")
        fake.connect = lambda *_args, **_kwargs: connection
        return patch.dict(sys.modules, {"psycopg": fake})

    def test_requires_dedicated_login_and_sets_only_reconciler_capability(self):
        connection = _Connection(
            "jas_si_github_reconciler_login",
            "jas_si_github_reconciler",
        )
        reconciler = PostgresGitHubInstallationReconciler(
            database_dsn="postgresql://dedicated-reconciler",
            github_api=_GitHub(),
        )
        with self._patch_psycopg(connection):
            result = reconciler._connect()
        self.assertIs(result, connection)
        self.assertEqual(
            connection.cursor_instance.statements,
            [
                "SELECT session_user",
                "SET ROLE jas_si_github_reconciler",
                "SELECT current_user",
            ],
        )
        self.assertFalse(connection.closed)

    def test_rejects_broad_runtime_database_login_before_setting_role(self):
        connection = _Connection("jas_si_runtime", "jas_si_runtime")
        reconciler = PostgresGitHubInstallationReconciler(
            database_dsn="postgresql://wrong-role",
            github_api=_GitHub(),
        )
        with self._patch_psycopg(connection):
            with self.assertRaises(RuntimeError):
                reconciler._connect()
        self.assertEqual(
            connection.cursor_instance.statements,
            ["SELECT session_user"],
        )
        self.assertTrue(connection.closed)

    def test_rejects_connection_that_did_not_assume_reconciler_capability(self):
        connection = _Connection(
            "jas_si_github_reconciler_login",
            "jas_si_github_reconciler_login",
        )
        reconciler = PostgresGitHubInstallationReconciler(
            database_dsn="postgresql://dedicated-reconciler",
            github_api=_GitHub(),
        )
        with self._patch_psycopg(connection):
            with self.assertRaises(RuntimeError):
                reconciler._connect()
        self.assertTrue(connection.closed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
