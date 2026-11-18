from __future__ import annotations

import os
import unittest
import uuid

import psycopg
from psycopg import errors


_DSN = os.environ.get("JAS_SI_MIGRATION_REPLAY_DATABASE_URL")


@unittest.skipUnless(_DSN, "PostgreSQL migration replay DSN is not configured")
class GitHubInstallationBindingPostgresTests(unittest.TestCase):
    tenant_a = uuid.UUID("00000000-0000-0000-0000-000000009401")
    tenant_b = uuid.UUID("00000000-0000-0000-0000-000000009402")
    installation_a = 994001
    installation_b = 994002
    repository = "fixture-owner/private-repo"

    @classmethod
    def setUpClass(cls):
        with psycopg.connect(_DSN) as conn:
            conn.execute(
                """
                INSERT INTO public.jas_si_tenants (tenant_id, tenant_name, status)
                VALUES (%s, 'github-binding-fixture-a', 'active'),
                       (%s, 'github-binding-fixture-b', 'active')
                """,
                (cls.tenant_a, cls.tenant_b),
            )
            conn.execute(
                """
                INSERT INTO public.jas_si_github_app_installations
                    (installation_id, tenant_id, account_login, status, verified_at)
                VALUES (%s, %s, 'fixture-owner', 'active', pg_catalog.clock_timestamp()),
                       (%s, %s, 'fixture-owner', 'active', pg_catalog.clock_timestamp())
                """,
                (cls.installation_a, cls.tenant_a, cls.installation_b, cls.tenant_b),
            )
            conn.execute(
                """
                INSERT INTO public.jas_si_github_app_installation_repositories
                    (installation_id, tenant_id, repository_full_name, status, verified_at)
                VALUES (%s, %s, %s, 'active', pg_catalog.clock_timestamp())
                """,
                (cls.installation_a, cls.tenant_a, cls.repository),
            )

    def _resolve_as(self, role: str, tenant_id: uuid.UUID):
        with psycopg.connect(_DSN) as conn:
            conn.execute(f"SET SESSION AUTHORIZATION {role}")
            row = conn.execute(
                """
                SELECT tenant_id, installation_id, repository_full_name
                  FROM public.jas_si_github_installation_binding_resolve(%s, %s)
                """,
                (tenant_id, self.repository),
            ).fetchone()
            conn.execute("RESET SESSION AUTHORIZATION")
            return row

    def test_worker_resolves_only_the_requested_tenants_binding(self):
        row = self._resolve_as("jas_si_agent_worker", self.tenant_a)
        self.assertEqual(row, (self.tenant_a, self.installation_a, self.repository))
        self.assertIsNone(self._resolve_as("jas_si_agent_worker", self.tenant_b))

    def test_verifier_can_resolve_verified_binding(self):
        row = self._resolve_as("jas_si_agent_verifier", self.tenant_a)
        self.assertEqual(row, (self.tenant_a, self.installation_a, self.repository))

    def test_pending_installation_never_resolves(self):
        with psycopg.connect(_DSN) as conn:
            conn.execute(
                """
                UPDATE public.jas_si_github_app_installations
                   SET status='pending', verified_at=NULL
                 WHERE installation_id=%s
                """,
                (self.installation_a,),
            )
        self.assertIsNone(self._resolve_as("jas_si_agent_worker", self.tenant_a))
        with psycopg.connect(_DSN) as conn:
            conn.execute(
                """
                UPDATE public.jas_si_github_app_installations
                   SET status='active', verified_at=pg_catalog.clock_timestamp()
                 WHERE installation_id=%s
                """,
                (self.installation_a,),
            )

    def test_suspended_tenant_never_resolves(self):
        with psycopg.connect(_DSN) as conn:
            conn.execute(
                "UPDATE public.jas_si_tenants SET status='suspended' WHERE tenant_id=%s",
                (self.tenant_a,),
            )
        self.assertIsNone(self._resolve_as("jas_si_agent_worker", self.tenant_a))
        with psycopg.connect(_DSN) as conn:
            conn.execute(
                "UPDATE public.jas_si_tenants SET status='active' WHERE tenant_id=%s",
                (self.tenant_a,),
            )

    def test_untrusted_runtime_identity_cannot_call_resolver(self):
        with psycopg.connect(_DSN) as conn:
            conn.execute("SET SESSION AUTHORIZATION jas_si_runtime")
            with self.assertRaises(errors.InsufficientPrivilege):
                conn.execute(
                    """
                    SELECT * FROM public.jas_si_github_installation_binding_resolve(%s, %s)
                    """,
                    (self.tenant_a, self.repository),
                )
            conn.rollback()
            conn.execute("RESET SESSION AUTHORIZATION")

    def test_worker_and_verifier_cannot_read_binding_tables_directly(self):
        for role in ("jas_si_agent_worker", "jas_si_agent_verifier"):
            with self.subTest(role=role), psycopg.connect(_DSN) as conn:
                conn.execute(f"SET SESSION AUTHORIZATION {role}")
                for table in (
                    "jas_si_github_app_installations",
                    "jas_si_github_app_installation_repositories",
                    "jas_si_tenants",
                ):
                    conn.execute("SAVEPOINT before_denied_read")
                    with self.assertRaises(errors.InsufficientPrivilege):
                        conn.execute(f"SELECT * FROM public.{table} LIMIT 1")
                    conn.execute("ROLLBACK TO SAVEPOINT before_denied_read")
                conn.execute("RESET SESSION AUTHORIZATION")


if __name__ == "__main__":
    unittest.main()
