from __future__ import annotations

import os
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from jas_si_agent import agent_task_verifier_supervisor as verifier_host
from jas_si_agent import agent_task_worker_supervisor as worker_host


class FakeHealthServer:
    def __init__(self, *_args, **_kwargs):
        self.started = False
        self.closed = False

    def start(self):
        self.started = True

    def close(self):
        self.closed = True


class GitHubAppRuntimeWiringTests(unittest.TestCase):
    def test_worker_main_injects_tenant_github_app_provider(self):
        worker = object()
        provider = object()
        env = {
            "JAS_SI_AGENT_WORKER_DSN": "postgresql://worker.invalid/db",
            "JAS_SI_AGENT_WORKER_ID": str(uuid4()),
            "JAS_SI_AGENT_WORKER_POLL_SECONDS": "1",
            "JAS_SI_AGENT_HEALTH_PORT": "8001",
            "GITHUB_APP_ID": "5818164",
            "GITHUB_APP_PRIVATE_KEY_PATH": "/run/secrets/github-app.pem",
        }
        health = FakeHealthServer()
        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(worker_host, "verify_agent_host_database_access") as preflight,
            patch.object(
                worker_host,
                "build_github_app_tenant_credential_provider",
                return_value=provider,
            ) as provider_factory,
            patch.object(
                worker_host, "build_github_repository_worker", return_value=worker
            ) as worker_factory,
            patch.object(worker_host, "AgentHostHealthServer", return_value=health),
            patch.object(worker_host, "run_worker_loop") as run_loop,
            patch.object(worker_host.signal, "signal"),
        ):
            worker_host.main()

        preflight.assert_called_once()
        provider_factory.assert_called_once_with(
            database_dsn=env["JAS_SI_AGENT_WORKER_DSN"],
            app_id=5818164,
            private_key_path=env["GITHUB_APP_PRIVATE_KEY_PATH"],
        )
        self.assertIs(worker_factory.call_args.kwargs["credential_provider"], provider)
        self.assertEqual(worker_factory.call_args.kwargs["worker_dsn"], env["JAS_SI_AGENT_WORKER_DSN"])
        run_loop.assert_called_once()
        self.assertTrue(health.started)
        self.assertTrue(health.closed)

    def test_verifier_main_injects_tenant_github_app_provider(self):
        verifier = object()
        provider = object()
        env = {
            "JAS_SI_AGENT_VERIFIER_DSN": "postgresql://verifier.invalid/db",
            "JAS_SI_AGENT_VERIFIER_POLL_SECONDS": "1",
            "JAS_SI_AGENT_VERIFIER_BATCH_SIZE": "7",
            "JAS_SI_AGENT_VERIFIER_COLLECTOR_ID": "staging-verifier-test",
            "JAS_SI_AGENT_HEALTH_PORT": "8002",
            "GITHUB_APP_ID": "5818164",
            "GITHUB_APP_PRIVATE_KEY_PATH": "/run/secrets/github-app.pem",
        }
        health = FakeHealthServer()
        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(verifier_host, "verify_agent_host_database_access") as preflight,
            patch.object(
                verifier_host,
                "build_github_app_tenant_credential_provider",
                return_value=provider,
            ) as provider_factory,
            patch.object(
                verifier_host,
                "build_github_repository_verifier",
                return_value=verifier,
            ) as verifier_factory,
            patch.object(verifier_host, "AgentHostHealthServer", return_value=health),
            patch.object(verifier_host, "run_verifier_loop") as run_loop,
            patch.object(verifier_host.signal, "signal"),
        ):
            verifier_host.main()

        preflight.assert_called_once()
        provider_factory.assert_called_once_with(
            database_dsn=env["JAS_SI_AGENT_VERIFIER_DSN"],
            app_id=5818164,
            private_key_path=env["GITHUB_APP_PRIVATE_KEY_PATH"],
        )
        self.assertIs(
            verifier_factory.call_args.kwargs["credential_provider"], provider
        )
        self.assertEqual(
            verifier_factory.call_args.kwargs["verifier_dsn"],
            env["JAS_SI_AGENT_VERIFIER_DSN"],
        )
        self.assertEqual(verifier_factory.call_args.kwargs["batch_size"], 7)
        run_loop.assert_called_once()
        self.assertTrue(health.started)
        self.assertTrue(health.closed)

    def test_worker_without_app_credentials_fails_closed_to_public_repositories(self):
        env = {
            "JAS_SI_AGENT_WORKER_DSN": "postgresql://worker.invalid/db",
            "JAS_SI_AGENT_WORKER_ID": str(uuid4()),
            "JAS_SI_AGENT_HEALTH_PORT": "8001",
        }
        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(worker_host, "verify_agent_host_database_access"),
            patch.object(worker_host, "build_github_repository_worker", return_value=object()) as factory,
            patch.object(worker_host, "AgentHostHealthServer", return_value=FakeHealthServer()),
            patch.object(worker_host, "run_worker_loop"),
            patch.object(worker_host.signal, "signal"),
        ):
            worker_host.main()

        provider = factory.call_args.kwargs["credential_provider"]
        self.assertIsNone(provider.resolve(tenant_id=uuid4(), repository="owner/repo"))

    def test_verifier_without_app_credentials_fails_closed_to_public_repositories(self):
        env = {"JAS_SI_AGENT_VERIFIER_DSN": "postgresql://verifier.invalid/db"}
        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(verifier_host, "verify_agent_host_database_access"),
            patch.object(verifier_host, "build_github_repository_verifier", return_value=object()) as factory,
            patch.object(verifier_host, "AgentHostHealthServer", return_value=FakeHealthServer()),
            patch.object(verifier_host, "run_verifier_loop"),
            patch.object(verifier_host.signal, "signal"),
        ):
            verifier_host.main()

        provider = factory.call_args.kwargs["credential_provider"]
        self.assertIsNone(provider.resolve(tenant_id=uuid4(), repository="owner/repo"))


if __name__ == "__main__":
    unittest.main()
