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
    ResolvedGitHubTaskCapability,
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


class GitHubCapabilityReadScopeTests(unittest.TestCase):
    def setUp(self):
        self.capability = ResolvedGitHubTaskCapability(
            task_id=uuid4(),
            tenant_id=uuid4(),
            installation_id=123456,
            repository_full_name="owner/private-repo",
            capability_role="worker",
            expires_at=datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc),
            commit_sha="a" * 40,
            repository_paths=["src/main.py", "tests/test_main.py"],
        )
        self.now = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)

    def test_accepts_exact_repository_commit_and_allowlisted_file(self):
        self.capability.authorize_read(
            repository="OWNER/private-repo", commit_sha="a" * 40,
            path="src/main.py", now=self.now,
        )

    def test_rejects_different_repository(self):
        with self.assertRaises(GitHubCapabilityBrokerError):
            self.capability.authorize_read(
                repository="attacker/private-repo", commit_sha="a" * 40,
                path="src/main.py", now=self.now,
            )

    def test_rejects_different_commit_even_when_path_is_allowed(self):
        with self.assertRaises(GitHubCapabilityBrokerError):
            self.capability.authorize_read(
                repository="owner/private-repo", commit_sha="b" * 40,
                path="src/main.py", now=self.now,
            )

    def test_rejects_unlisted_path_and_directory_prefix(self):
        for path in ("src/secret.py", "src", "src/../secret.py", "/src/main.py", "src\\main.py"):
            with self.subTest(path=path), self.assertRaises(GitHubCapabilityBrokerError):
                self.capability.authorize_read(
                    repository="owner/private-repo", commit_sha="a" * 40,
                    path=path, now=self.now,
                )

    def test_rejects_expired_capability(self):
        with self.assertRaises(GitHubCapabilityBrokerError):
            self.capability.authorize_read(
                repository="owner/private-repo", commit_sha="a" * 40,
                path="src/main.py", now=datetime(2026, 11, 25, tzinfo=timezone.utc),
            )


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
        self.assertEqual(
            paths,
            {
                "/internal/github/capabilities/resolve",
                "/internal/github/capabilities/read",
            },
        )
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


class ASGITLSClientCertificateTransportTests(unittest.TestCase):
    """Exercise the ASGI TLS extension boundary; not a real TCP mTLS test."""

    @classmethod
    def setUpClass(cls):
        from datetime import timedelta
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        now = datetime.now(timezone.utc)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "jas-si-asgi-tls-test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before((now - timedelta(minutes=5)).replace(tzinfo=None))
            .not_valid_after((now + timedelta(hours=1)).replace(tzinfo=None))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
            .sign(key, hashes.SHA256())
        )
        cls.pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        cls.der = cert.public_bytes(serialization.Encoding.DER)

    def _middleware_scope(self, *, tls=None, headers=None, state=None, scope_type="http"):
        scope = {
            "type": scope_type,
            "asgi": {"version": "3.0"},
            "headers": headers or [],
            "state": state if state is not None else {},
        }
        if tls is not None:
            scope["extensions"] = {"tls": tls}
        return scope

    def _run(self, scope):
        import asyncio
        from jas_si_agent.github_capability_asgi_tls import ASGITLSClientCertificateMiddleware

        class Capture:
            received = None
            async def __call__(self, forwarded_scope, receive, send):
                self.received = forwarded_scope

        app = Capture()
        asyncio.run(ASGITLSClientCertificateMiddleware(app)(scope, lambda: None, lambda msg: None))
        return app.received

    def test_tls_03_leaf_certificate_is_attached_as_der(self):
        forwarded = self._run(self._middleware_scope(tls={
            "spec_version": "0.3", "client_cert_chain": [self.pem],
        }))
        self.assertEqual(forwarded["state"]["verified_client_certificate_der"], self.der)

    def test_tls_02_verified_leaf_certificate_is_attached_as_der(self):
        forwarded = self._run(self._middleware_scope(tls={
            "spec_version": "0.2", "client_cert_error": None,
            "client_cert_chain": [self.pem],
        }))
        self.assertEqual(forwarded["state"]["verified_client_certificate_der"], self.der)

    def test_chain_uses_leaf_certificate_only(self):
        forwarded = self._run(self._middleware_scope(tls={
            "spec_version": "0.3", "client_cert_chain": [self.pem, self.pem],
        }))
        self.assertEqual(forwarded["state"]["verified_client_certificate_der"], self.der)

    def test_missing_tls_extension_ignores_spoofed_headers_and_clears_stale_state(self):
        scope = self._middleware_scope(
            headers=[(b"x-workload-identity", b"worker.staging.instance-1")],
            state={"verified_client_certificate_der": b"stale-untrusted-value"},
        )
        forwarded = self._run(scope)
        self.assertNotIn("verified_client_certificate_der", forwarded["state"])

    def test_tls_verification_error_fails_closed(self):
        from jas_si_agent.github_capability_asgi_tls import _client_certificate_der
        scope = self._middleware_scope(tls={
            "spec_version": "0.2", "client_cert_error": "certificate verify failed",
            "client_cert_chain": [self.pem],
        })
        self.assertIsNone(_client_certificate_der(scope))

    def test_unsupported_tls_extension_version_fails_closed(self):
        from jas_si_agent.github_capability_asgi_tls import _client_certificate_der
        scope = self._middleware_scope(tls={
            "spec_version": "9.9", "client_cert_chain": [self.pem],
        })
        self.assertIsNone(_client_certificate_der(scope))

    def test_malformed_and_oversized_chains_fail_closed(self):
        from jas_si_agent.github_capability_asgi_tls import _client_certificate_der
        malformed = self._middleware_scope(tls={
            "spec_version": "0.3", "client_cert_chain": ["not PEM"],
        })
        oversized = self._middleware_scope(tls={
            "spec_version": "0.3", "client_cert_chain": [self.pem] * 9,
        })
        self.assertIsNone(_client_certificate_der(malformed))
        self.assertIsNone(_client_certificate_der(oversized))

    def test_non_http_scope_is_forwarded_without_mutation(self):
        state = {"preserve": "me"}
        scope = self._middleware_scope(
            tls={"spec_version": "0.3", "client_cert_chain": [self.pem]},
            state=state, scope_type="lifespan",
        )
        forwarded = self._run(scope)
        self.assertIs(forwarded, scope)
        self.assertEqual(forwarded["state"], {"preserve": "me"})



if __name__ == "__main__":
    unittest.main(verbosity=2)
