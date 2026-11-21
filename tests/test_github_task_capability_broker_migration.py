from __future__ import annotations

import os
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "src" / "jas_si_agent" / "migrations" / "20261215_github_task_capability_broker.sql"


class CapabilityBrokerMigrationContractTests(unittest.TestCase):
    def test_broker_migration_is_fail_closed_and_task_scoped(self):
        sql = MIGRATION.read_text(encoding="utf-8").lower()
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
            "q.input_payload->>'commit_sha'",
            "q.input_payload->'paths'",
            "t.status='active'",
            "i.status='active'",
            "r.status='active'",
            "from public,jas_si_agent_worker,jas_si_agent_verifier",
            "to jas_si_agent_capability_broker",
            "set search_path=pg_catalog",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, sql)

    def test_migration_does_not_provision_login_credentials_or_share_capability(self):
        sql = MIGRATION.read_text(encoding="utf-8").lower()
        self.assertNotIn("create role jas_si_agent_capability_broker login", sql)
        self.assertNotIn("password", sql)
        self.assertNotIn("grant jas_si_agent_capability_broker to jas_si_agent_worker", sql)

    @unittest.skipUnless(os.getenv("JAS_SI_BROKER_MIGRATION_TEST_DSN"), "PostgreSQL migration integration DSN not configured")
    def test_clean_schema_migration_replays_and_acl_is_broker_only(self):
        import psycopg

        dsn = os.environ["JAS_SI_BROKER_MIGRATION_TEST_DSN"]
        schema = """
        CREATE ROLE jas_si_agent_task_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
        CREATE ROLE jas_si_agent_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
        CREATE ROLE jas_si_agent_verifier NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
        CREATE ROLE jas_si_agent_worker_login LOGIN PASSWORD 'worker-test-secret' NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
        CREATE ROLE jas_si_agent_verifier_login LOGIN PASSWORD 'verifier-test-secret' NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
        GRANT jas_si_agent_worker TO jas_si_agent_worker_login WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
        GRANT jas_si_agent_verifier TO jas_si_agent_verifier_login WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
        CREATE TABLE public.jas_si_tenants(tenant_id uuid PRIMARY KEY,status text NOT NULL);
        CREATE TABLE public.jas_si_agent_tasks(
          task_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,task_type text NOT NULL,status text NOT NULL,
          input_payload jsonb NOT NULL,lease_owner_principal name,lease_expires_at timestamptz,
          lease_fence bigint NOT NULL,verifier_claim_owner name,verifier_claim_token uuid,
          verifier_lease_expires_at timestamptz,verifier_attempt_count integer NOT NULL);
        CREATE TABLE public.jas_si_github_app_installations(
          installation_id bigint PRIMARY KEY,tenant_id uuid NOT NULL,status text NOT NULL,verified_at timestamptz);
        CREATE TABLE public.jas_si_github_app_installation_repositories(
          installation_id bigint NOT NULL,tenant_id uuid NOT NULL,repository_full_name text NOT NULL,
          status text NOT NULL,verified_at timestamptz);
        ALTER TABLE public.jas_si_tenants ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_tenants FORCE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_agent_tasks ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_agent_tasks FORCE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_github_app_installations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_github_app_installations FORCE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_github_app_installation_repositories ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_github_app_installation_repositories FORCE ROW LEVEL SECURITY;
        GRANT USAGE ON SCHEMA public TO jas_si_agent_task_owner;
        GRANT SELECT ON public.jas_si_tenants,public.jas_si_agent_tasks,
          public.jas_si_github_app_installations,public.jas_si_github_app_installation_repositories
          TO jas_si_agent_task_owner;
        CREATE POLICY tenant_taskowner_read ON public.jas_si_tenants FOR SELECT TO jas_si_agent_task_owner USING(true);
        CREATE POLICY task_taskowner_read ON public.jas_si_agent_tasks FOR SELECT TO jas_si_agent_task_owner USING(true);
        CREATE POLICY install_taskowner_read ON public.jas_si_github_app_installations FOR SELECT TO jas_si_agent_task_owner USING(true);
        CREATE POLICY repo_taskowner_read ON public.jas_si_github_app_installation_repositories FOR SELECT TO jas_si_agent_task_owner USING(true);
        """
        migration = MIGRATION.read_text(encoding="utf-8")
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(schema)
            admin.execute(migration)
            admin.execute(migration)  # Idempotency/replay check.
            admin.execute("CREATE ROLE jas_si_agent_broker_login_test LOGIN PASSWORD 'broker-test-secret' NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS")
            admin.execute("GRANT jas_si_agent_capability_broker TO jas_si_agent_broker_login_test WITH ADMIN FALSE, INHERIT FALSE, SET TRUE")
            admin.execute("INSERT INTO public.jas_si_tenants VALUES ('11111111-1111-4111-8111-111111111111','active')")
            admin.execute("INSERT INTO public.jas_si_agent_tasks VALUES ('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111','github.read_repository','running',%s,'jas_si_agent_broker_login_test',now()+interval '5 minutes',4,NULL,NULL,NULL,0)", ('{"repository":"octo/repo","commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","paths":["README.md"]}',))
            admin.execute("INSERT INTO public.jas_si_github_app_installations VALUES (123,'11111111-1111-4111-8111-111111111111','active',now())")
            admin.execute("INSERT INTO public.jas_si_github_app_installation_repositories VALUES (123,'11111111-1111-4111-8111-111111111111','octo/repo','active',now())")
            admin.execute("GRANT USAGE ON SCHEMA public TO jas_si_agent_capability_broker")
            admin.execute("GRANT SELECT ON public.jas_si_agent_tasks,public.jas_si_tenants,public.jas_si_github_app_installations,public.jas_si_github_app_installation_repositories TO jas_si_agent_task_owner")
            # The routine is SECURITY DEFINER, owned by the task owner, and the
            # task-owner policies make the minimal persisted lookup available.
        with psycopg.connect("postgresql://jas_si_agent_broker_login_test:broker-test-secret@localhost:5432/postgres") as broker:
            row = broker.execute(
                "SELECT task_id,tenant_id,installation_id,repository_full_name,capability_role,fence,commit_sha,repository_paths FROM public.jas_si_github_task_capability_resolve(%s,%s,'worker',4,NULL)",
                ("22222222-2222-4222-8222-222222222222","jas_si_agent_broker_login_test"),
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[2],123)
            self.assertEqual(row[3],"octo/repo")
            self.assertEqual(row[6],"a"*40)
            stale = broker.execute(
                "SELECT 1 FROM public.jas_si_github_task_capability_resolve(%s,%s,'worker',3,NULL)",
                ("22222222-2222-4222-8222-222222222222","jas_si_agent_broker_login_test"),
            ).fetchone()
            self.assertIsNone(stale)
        with psycopg.connect(dsn) as admin:
            self.assertFalse(admin.execute("SELECT has_function_privilege('jas_si_agent_worker','public.jas_si_github_task_capability_resolve(uuid,name,text,bigint,uuid)','EXECUTE')").fetchone()[0])
            self.assertFalse(admin.execute("SELECT has_function_privilege('jas_si_agent_verifier','public.jas_si_github_task_capability_resolve(uuid,name,text,bigint,uuid)','EXECUTE')").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
