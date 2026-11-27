from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.github_capability_identity import WorkloadIdentity
from jas_si_agent.github_capability_broker import (
    GitHubCapabilityBrokerError,
    PostgresGitHubCapabilityBroker,
)


class _Cursor:
    def __init__(self, row, session_user="jas_si_agent_broker_login"):
        self.rows = [(session_user,), row]
        self.statements = []
        self.parameters = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, statement, parameters=None):
        self.statements.append(statement)
        self.parameters.append(parameters)

    def fetchone(self):
        return self.rows.pop(0)


class _Connection:
    def __init__(self, row, session_user="jas_si_agent_broker_login"):
        self.cursor_value = _Cursor(row, session_user=session_user)
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True
        return False

    def cursor(self):
        return self.cursor_value


class GitHubCapabilityBrokerTests(unittest.TestCase):
    def setUp(self):
        self.task_id = uuid4()
        self.tenant_id = uuid4()
        self.identity = WorkloadIdentity("worker.staging.instance-1", "worker")
        self.verifier_identity = WorkloadIdentity("verifier.staging.instance-1", "verifier")
        self.claim_token = uuid4()
        self.expires_at = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
        self.row = (
            self.task_id,
            self.tenant_id,
            123456,
            "owner/private-repo",
            "worker",
            7,
            None,
            self.expires_at,
            "a" * 40,
            ["src/main.py", "tests/test_main.py"],
        )

    def test_requires_tls_hostname_verification_in_database_dsn(self):
        with self.assertRaisesRegex(ValueError, "sslmode=verify-full"):
            PostgresGitHubCapabilityBroker("postgresql://user:pass@db.example.test/db?sslmode=require")

    def test_worker_resolution_sets_broker_role_and_uses_registry_identity(self):
        connection = _Connection(self.row)
        with patch("jas_si_agent.github_capability_broker.psycopg.connect", return_value=connection) as connect:
            broker = PostgresGitHubCapabilityBroker(
                "postgresql://broker:secret@db.example.test/db?sslmode=verify-full"
            )
            result = broker.resolve(
                task_id=self.task_id,
                identity=self.identity,
                lease_fence=7,
            )

        self.assertEqual(result.task_id, self.task_id)
        self.assertEqual(result.repository_full_name, "owner/private-repo")
        self.assertEqual(result.repository_paths, ["src/main.py", "tests/test_main.py"])
        self.assertEqual(connection.cursor_value.statements[0], "SELECT session_user")
        self.assertEqual(connection.cursor_value.statements[1], "SET ROLE jas_si_agent_capability_broker")
        self.assertEqual(
            connection.cursor_value.parameters[2],
            (self.task_id, "worker.staging.instance-1", "worker", 7, None),
        )
        self.assertEqual(connect.call_args.kwargs["application_name"], "jas-si-github-capability-broker")
        self.assertTrue(connection.closed)

    def test_rejects_non_dedicated_database_login_before_set_role(self):
        connection = _Connection(self.row, session_user="neondb_owner")
        with patch("jas_si_agent.github_capability_broker.psycopg.connect", return_value=connection):
            broker = PostgresGitHubCapabilityBroker(
                "postgresql://broker:secret@db.example.test/db?sslmode=verify-full"
            )
            with self.assertRaisesRegex(
                GitHubCapabilityBrokerError, "login identity is not authorized"
            ):
                broker.resolve(
                    task_id=self.task_id,
                    identity=self.identity,
                    lease_fence=7,
                )

        self.assertEqual(connection.cursor_value.statements, ["SELECT session_user"])
        self.assertTrue(connection.closed)

    def test_verifier_resolution_uses_claim_token_not_worker_fence(self):
        row = self.row[:4] + ("verifier",) + (None, self.claim_token) + self.row[7:]
        connection = _Connection(row)
        with patch("jas_si_agent.github_capability_broker.psycopg.connect", return_value=connection):
            broker = PostgresGitHubCapabilityBroker(
                "postgresql://broker:secret@db.example.test/db?sslmode=verify-full"
            )
            result = broker.resolve(
                task_id=self.task_id,
                identity=self.verifier_identity,
                verifier_claim_token=self.claim_token,
            )
        self.assertEqual(result.capability_role, "verifier")
        self.assertEqual(
            connection.cursor_value.parameters[2],
            (self.task_id, "verifier.staging.instance-1", "verifier", None, self.claim_token),
        )

    def test_principal_longer_than_postgresql_name_limit_is_rejected(self):
        broker = PostgresGitHubCapabilityBroker(
            "postgresql://broker:secret@db.example.test/db?sslmode=verify-full"
        )
        with self.assertRaises(GitHubCapabilityBrokerError):
            broker.resolve(
                task_id=self.task_id,
                identity=WorkloadIdentity("w" * 64, "worker"),
                lease_fence=7,
            )

    def test_worker_cannot_supply_verifier_claim_token(self):
        broker = PostgresGitHubCapabilityBroker(
            "postgresql://broker:secret@db.example.test/db?sslmode=verify-full"
        )
        with self.assertRaises(GitHubCapabilityBrokerError):
            broker.resolve(
                task_id=self.task_id,
                identity=self.identity,
                lease_fence=7,
                verifier_claim_token=self.claim_token,
            )

    def test_verifier_cannot_supply_worker_fence(self):
        broker = PostgresGitHubCapabilityBroker(
            "postgresql://broker:secret@db.example.test/db?sslmode=verify-full"
        )
        with self.assertRaises(GitHubCapabilityBrokerError):
            broker.resolve(
                task_id=self.task_id,
                identity=self.verifier_identity,
                lease_fence=7,
                verifier_claim_token=self.claim_token,
            )

    def test_no_database_row_means_no_authorization(self):
        connection = _Connection(None)
        with patch("jas_si_agent.github_capability_broker.psycopg.connect", return_value=connection):
            broker = PostgresGitHubCapabilityBroker(
                "postgresql://broker:secret@db.example.test/db?sslmode=verify-full"
            )
            self.assertIsNone(broker.resolve(
                task_id=self.task_id,
                identity=self.identity,
                lease_fence=7,
            ))

    def test_database_errors_are_redacted(self):
        with patch(
            "jas_si_agent.github_capability_broker.psycopg.connect",
            side_effect=RuntimeError("postgres://secret@db/private"),
        ):
            broker = PostgresGitHubCapabilityBroker(
                "postgresql://broker:secret@db.example.test/db?sslmode=verify-full"
            )
            with self.assertRaises(GitHubCapabilityBrokerError) as raised:
                broker.resolve(
                    task_id=self.task_id,
                    identity=self.identity,
                    lease_fence=7,
                )
        self.assertNotIn("secret", str(raised.exception))
        self.assertNotIn("postgres://", str(raised.exception))


