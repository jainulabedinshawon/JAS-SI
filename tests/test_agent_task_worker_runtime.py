from __future__ import annotations

import unittest
import uuid
from unittest.mock import patch

from jas_si_agent.agent_task_worker_runtime import build_github_repository_worker


class FakeWorkerStore:
    def claim(self, **kwargs):
        return None

    def renew(self, **kwargs):
        return True

    def acknowledge_cancel(self, **kwargs):
        return True

    def report(self, **kwargs):
        return True

    def fail(self, **kwargs):
        return "failed"


class FakeCredentialProvider:
    def resolve(self, *, tenant_id, repository):
        return None


class AgentTaskWorkerRuntimeTests(unittest.TestCase):
    def test_factory_composes_only_the_explicit_read_only_handler(self):
        worker_id = uuid.uuid4()
        store = FakeWorkerStore()
        with patch(
            "jas_si_agent.agent_task_worker_runtime.PostgresAgentTaskWorkerStore",
            return_value=store,
        ) as store_factory:
            worker = build_github_repository_worker(
                worker_dsn="postgresql://worker:test@localhost/jas_si",
                worker_id=worker_id,
                credential_provider=FakeCredentialProvider(),
                lease_seconds=45,
            )

        store_factory.assert_called_once_with(
            "postgresql://worker:test@localhost/jas_si",
            worker_id,
        )
        self.assertEqual(set(worker._handlers), {"github.read_repository"})
        self.assertEqual(worker._lease_seconds, 45)
        self.assertIs(worker._store, store)

    def test_factory_rejects_missing_worker_dsn(self):
        with self.assertRaisesRegex(ValueError, "dedicated worker PostgreSQL DSN"):
            build_github_repository_worker(
                worker_dsn=" ",
                worker_id=uuid.uuid4(),
                credential_provider=FakeCredentialProvider(),
            )

    def test_factory_rejects_missing_trusted_credential_provider(self):
        with self.assertRaisesRegex(ValueError, "trusted tenant GitHub credential"):
            build_github_repository_worker(
                worker_dsn="postgresql://worker:test@localhost/jas_si",
                worker_id=uuid.uuid4(),
                credential_provider=None,
            )


if __name__ == "__main__":
    unittest.main()
