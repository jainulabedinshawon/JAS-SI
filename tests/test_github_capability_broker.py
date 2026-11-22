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
from jas_si_agent.github_capability_identity import (
    CertificateWorkloadIdentityRegistry,
    WorkloadIdentity,
)
from jas_si_agent import api as api_module
from jas_si_agent.github_capability_runtime import (
    GitHubCapabilityResolveRequest,
    create_github_capability_app,
    require_enabled_authenticated_workload,
)
from types import SimpleNamespace


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
                    principal_id="worker.staging.instance-1",
                    role="worker",
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
                principal_id="verifier.staging.instance-1",
                role="verifier",
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
                principal_id="w" * 64,
                role="worker",
                lease_fence=7,
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


def _broker_settings(*, enabled=True, environment="preview", registry=None):
    return SimpleNamespace(
        github_capability_broker_enabled=enabled,
        environment=environment,
        github_capability_broker_database_url=(
            "postgresql://broker:secret@db.example.test/db?sslmode=verify-full"
        ),
        github_capability_workload_identities=registry,
    )


class GitHubCapabilityBrokerIsolationTests(unittest.TestCase):
    def test_public_api_has_no_broker_route(self):
        paths = {
            getattr(route, "path", None)
            for route in api_module.app.routes
        }
        self.assertNotIn("/internal/github/capabilities/resolve", paths)

    def test_dedicated_app_exposes_only_broker_route_and_disables_docs(self):
        app = create_github_capability_app(_broker_settings())
        paths = {
            getattr(route, "path", None)
            for route in app.routes
        }
        self.assertEqual(paths, {"/internal/github/capabilities/resolve"})
        self.assertIsNone(app.docs_url)
        self.assertIsNone(app.redoc_url)
        self.assertIsNone(app.openapi_url)

    def test_route_uses_request_app_state_and_certificate_registry_identity(self):
        from fastapi.testclient import TestClient

        broker = _FakeBroker()
        app = create_github_capability_app(
            _broker_settings(),
            broker_factory=lambda dsn: broker,
        )
        workload = WorkloadIdentity("worker.staging.instance-1", "worker")
        app.dependency_overrides[require_enabled_authenticated_workload] = (
            lambda: workload
        )
        task_id = uuid4()
        with TestClient(app) as client:
            response = client.post(
                "/internal/github/capabilities/resolve",
                json={"task_id": str(task_id), "lease_fence": 9},
            )

        self.assertEqual(response.status_code, 200)
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
        self.assertEqual(response.json()["repository"], "owner/private-repo")
        self.assertNotIn("access_token", response.json())
        self.assertNotIn("principal_id", response.json())

    def test_disabled_broker_fails_closed_before_certificate_lookup(self):
        from fastapi.testclient import TestClient

        app = create_github_capability_app(_broker_settings(enabled=False))
        with TestClient(app) as client:
            response = client.post(
                "/internal/github/capabilities/resolve",
                json={"task_id": str(uuid4()), "lease_fence": 1},
            )
        self.assertEqual(response.status_code, 404)

    def test_production_environment_cannot_enable_broker(self):
        from fastapi.testclient import TestClient

        app = create_github_capability_app(
            _broker_settings(enabled=True, environment="production")
        )
        with TestClient(app) as client:
            response = client.post(
                "/internal/github/capabilities/resolve",
                json={"task_id": str(uuid4()), "lease_fence": 1},
            )
        self.assertEqual(response.status_code, 404)

    def test_missing_peer_certificate_fails_closed(self):
        from fastapi.testclient import TestClient

        registry = CertificateWorkloadIdentityRegistry(
            {"a" * 64: WorkloadIdentity("worker.staging.instance-1", "worker")}
        )
        app = create_github_capability_app(
            _broker_settings(registry=registry)
        )
        with TestClient(app) as client:
            response = client.post(
                "/internal/github/capabilities/resolve",
                json={"task_id": str(uuid4()), "lease_fence": 1},
            )
        self.assertEqual(response.status_code, 401)

    def test_request_model_rejects_client_supplied_identity_fields(self):
        with self.assertRaises(Exception):
            GitHubCapabilityResolveRequest(
                task_id=uuid4(),
                lease_fence=1,
                principal_id="attacker",
                role="worker",
            )

    def test_boolean_lease_fence_is_rejected(self):
        with self.assertRaises(Exception):
            GitHubCapabilityResolveRequest(task_id=uuid4(), lease_fence=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
