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

from jas_si_agent.github_capability_broker import (
    GitHubCapabilityBrokerError,
    PostgresGitHubCapabilityBroker,
)
from jas_si_agent.github_capability_identity import WorkloadIdentity
from jas_si_agent import api as api_module
from types import SimpleNamespace


class _Cursor:
    def __init__(self, row):
        self.row = row
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
        return self.row


class _Connection:
    def __init__(self, row):
        self.cursor_value = _Cursor(row)
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
                principal_id="worker.staging.instance-1",
                role="worker",
                lease_fence=7,
            )

        self.assertEqual(result.task_id, self.task_id)
        self.assertEqual(result.repository_full_name, "owner/private-repo")
        self.assertEqual(result.repository_paths, ["src/main.py", "tests/test_main.py"])
        self.assertEqual(connection.cursor_value.statements[0], "SET ROLE jas_si_agent_capability_broker")
        self.assertEqual(
            connection.cursor_value.parameters[1],
            (self.task_id, "worker.staging.instance-1", "worker", 7, None),
        )
        self.assertEqual(connect.call_args.kwargs["application_name"], "jas-si-github-capability-broker")
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
                principal_id="verifier.staging.instance-1",
                role="verifier",
                verifier_claim_token=self.claim_token,
            )
        self.assertEqual(result.capability_role, "verifier")
        self.assertEqual(
            connection.cursor_value.parameters[1],
            (self.task_id, "verifier.staging.instance-1", "verifier", None, self.claim_token),
        )

    def test_worker_cannot_supply_verifier_claim_token(self):
        broker = PostgresGitHubCapabilityBroker(
            "postgresql://broker:secret@db.example.test/db?sslmode=verify-full"
        )
        with self.assertRaises(GitHubCapabilityBrokerError):
            broker.resolve(
                task_id=self.task_id,
                principal_id="worker.staging.instance-1",
                role="worker",
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
                principal_id="verifier.staging.instance-1",
                role="verifier",
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
                principal_id="worker.staging.instance-1",
                role="worker",
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
                    principal_id="worker.staging.instance-1",
                    role="worker",
                    lease_fence=7,
                )
        self.assertNotIn("secret", str(raised.exception))
        self.assertNotIn("postgres://", str(raised.exception))


class _FakeResolvedCapability:
    def __init__(self, task_id):
        self.task_id = task_id
        self.tenant_id = uuid4()
        self.installation_id = 123456
        self.repository_full_name = "owner/private-repo"
        self.capability_role = "worker"
        self.expires_at = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
        self.commit_sha = "b" * 40
        self.repository_paths = ["src/main.py"]


class _FakeBroker:
    def __init__(self):
        self.arguments = None

    def resolve(self, **kwargs):
        self.arguments = kwargs
        return _FakeResolvedCapability(kwargs["task_id"])


class GitHubCapabilityBrokerRouteTests(unittest.TestCase):
    def tearDown(self):
        if hasattr(api_module.app.state, "github_capability_broker"):
            delattr(api_module.app.state, "github_capability_broker")

    def test_route_uses_certificate_registry_identity_and_returns_metadata_only(self):
        broker = _FakeBroker()
        api_module.app.state.github_capability_broker = broker
        task_id = uuid4()
        payload = api_module.GitHubCapabilityResolveRequest(
            task_id=task_id,
            lease_fence=9,
        )
        workload = WorkloadIdentity("worker.staging.instance-1", "worker")
        with patch.object(
            api_module,
            "settings",
            SimpleNamespace(
                github_capability_broker_enabled=True,
                environment="preview",
                github_capability_broker_database_url=(
                    "postgresql://broker:secret@db.example.test/db?sslmode=verify-full"
                )
            ),
        ):
            result = api_module.resolve_github_task_capability(payload, workload)

        self.assertEqual(
            broker.arguments,
            {
                "task_id": task_id,
                "principal_id": "worker.staging.instance-1",
                "role": "worker",
                "lease_fence": 9,
                "verifier_claim_token": None,
            },
        )
        self.assertEqual(result["repository"], "owner/private-repo")
        self.assertNotIn("access_token", result)
        self.assertNotIn("principal_id", result)

    def test_request_model_rejects_client_supplied_identity_fields(self):
        with self.assertRaises(Exception):
            api_module.GitHubCapabilityResolveRequest(
                task_id=uuid4(),
                lease_fence=1,
                principal_id="attacker",
                role="worker",
            )

    def test_route_kill_switch_precedes_certificate_identity(self):
        from fastapi.testclient import TestClient
        with patch.object(api_module, "settings", SimpleNamespace(github_capability_broker_enabled=False, environment="preview", github_capability_broker_database_url=None)):
            response = TestClient(api_module.app).post("/internal/github/capabilities/resolve", json={"task_id": str(uuid4()), "lease_fence": 1})
        self.assertEqual(response.status_code, 404)

    def test_production_environment_cannot_enable_broker_route(self):
        from fastapi.testclient import TestClient
        with patch.object(api_module, "settings", SimpleNamespace(github_capability_broker_enabled=True, environment="production", github_capability_broker_database_url="postgresql://broker:secret@db.example.test/db?sslmode=verify-full")):
            response = TestClient(api_module.app).post("/internal/github/capabilities/resolve", json={"task_id": str(uuid4()), "lease_fence": 1})
        self.assertEqual(response.status_code, 404)

    def test_boolean_lease_fence_is_rejected(self):
        with self.assertRaises(Exception):
            api_module.GitHubCapabilityResolveRequest(task_id=uuid4(), lease_fence=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
