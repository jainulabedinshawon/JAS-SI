from __future__ import annotations

import unittest
from pathlib import Path


class CapabilityBrokerMigrationContractTests(unittest.TestCase):
    def test_broker_migration_is_fail_closed_and_task_scoped(self):
        root = Path(__file__).resolve().parents[1]
        path = root / "src" / "jas_si_agent" / "migrations" / "20261215_github_task_capability_broker.sql"
        sql = path.read_text(encoding="utf-8").lower()
        required = (
            "jas_si_agent_capability_broker",
            "jas_si_github_task_capability_resolve",
            "pg_has_role(session_user",
            "lease_owner_principal",
            "lease_fence=p_lease_fence",
            "lease_expires_at>v_now",
            "verifier_claim_owner",
            "verifier_claim_token=p_verifier_claim_token",
            "verifier_lease_expires_at>v_now",
            "q.task_type='github.read_repository'",
            "t.status='active'",
            "i.status='active'",
            "r.status='active'",
            "revoke all on function",
            "from public,jas_si_agent_worker,jas_si_agent_verifier",
            "grant execute on function",
            "to jas_si_agent_capability_broker",
            "set search_path=pg_catalog",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, sql)

    def test_broker_migration_does_not_create_or_grant_login_credentials(self):
        root = Path(__file__).resolve().parents[1]
        sql = (root / "src" / "jas_si_agent" / "migrations" / "20261215_github_task_capability_broker.sql").read_text(encoding="utf-8").lower()
        self.assertNotIn(" create role jas_si_agent_capability_broker login", sql)
        self.assertNotIn("password", sql)
        self.assertNotIn("grant jas_si_agent_agent_task_owner", sql)


if __name__ == "__main__":
    unittest.main()
