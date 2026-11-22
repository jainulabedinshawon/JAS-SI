from __future__ import annotations

import os
import unittest
from unittest.mock import patch
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
    def test_worker_rejects_app_signing_material(self):
        env = {
            "JAS_SI_AGENT_WORKER_DSN": "postgresql://worker.invalid/db",
            "JAS_SI_AGENT_WORKER_ID": str(uuid4()),
            "JAS_SI_GITHUB_APP_ID": "5818164",
            "JAS_SI_GITHUB_APP_PRIVATE_KEY_B64": "not-a-real-key",
        }
        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(worker_host, "verify_agent_host_database_access"),
        ):
            with self.assertRaisesRegex(SystemExit, "restricted to the isolated reconciler"):
                worker_host.main()

    def test_verifier_rejects_app_signing_material(self):
        env = {
            "JAS_SI_AGENT_VERIFIER_DSN": "postgresql://verifier.invalid/db",
            "JAS_SI_GITHUB_APP_ID": "5818164",
            "JAS_SI_GITHUB_APP_PRIVATE_KEY_B64": "not-a-real-key",
        }
        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(verifier_host, "verify_agent_host_database_access"),
        ):
            with self.assertRaisesRegex(SystemExit, "restricted to the isolated reconciler"):
                verifier_host.main()

    def test_worker_rejects_legacy_private_key_path(self):
        env = {
            "JAS_SI_AGENT_WORKER_DSN": "postgresql://worker.invalid/db",
            "JAS_SI_AGENT_WORKER_ID": str(uuid4()),
            "GITHUB_APP_PRIVATE_KEY_PATH": "/run/secrets/github-app.pem",
        }
        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(worker_host, "verify_agent_host_database_access"),
        ):
            with self.assertRaisesRegex(SystemExit, "restricted to the isolated reconciler"):
                worker_host.main()

    def test_verifier_rejects_legacy_app_id(self):
        env = {
            "JAS_SI_AGENT_VERIFIER_DSN": "postgresql://verifier.invalid/db",
            "GITHUB_APP_ID": "5818164",
        }
        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(verifier_host, "verify_agent_host_database_access"),
        ):
            with self.assertRaisesRegex(SystemExit, "restricted to the isolated reconciler"):
                verifier_host.main()

    def test_worker_without_app_credentials_is_public_repository_only(self):
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

    def test_verifier_without_app_credentials_is_public_repository_only(self):
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
