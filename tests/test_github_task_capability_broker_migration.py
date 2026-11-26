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
            "jas_si_github_installation_binding_resolve",
            "revoke all on function public.jas_si_github_installation_binding_resolve",
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
        CREATE FUNCTION public.jas_si_github_installation_binding_resolve(p_tenant_id uuid,p_repository_full_name text)
          RETURNS TABLE(tenant_id uuid,installation_id bigint,repository_full_name text)
          LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog
          AS $stub$ SELECT NULL::uuid,NULL::bigint,NULL::text WHERE false $stub$;
        GRANT CREATE ON SCHEMA public TO jas_si_agent_task_owner;
        ALTER FUNCTION public.jas_si_github_installation_binding_resolve(uuid,text) OWNER TO jas_si_agent_task_owner;
        GRANT EXECUTE ON FUNCTION public.jas_si_github_installation_binding_resolve(uuid,text)
          TO jas_si_agent_worker,jas_si_agent_verifier;
        ALTER TABLE public.jas_si_tenants ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_tenants FORCE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_agent_tasks ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_agent_tasks FORCE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_github_app_installations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_github_app_installations FORCE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_github_app_installation_repositories ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.jas_si_github_app_installation_repositories FORCE ROW LEVEL SECURITY;
        GRANT USAGE ON SCHEMA public TO jas_si_agent_task_owner;
        GRANT SELECT ON public.jas_si_agent_tasks,
          public.jas_si_github_app_installations,public.jas_si_github_app_installation_repositories
          TO jas_si_agent_task_owner;
        CREATE POLICY tenant_taskowner_read ON public.jas_si_tenants FOR SELECT TO jas_si_agent_task_owner USING(true);
        CREATE POLICY task_taskowner_read ON public.jas_si_agent_tasks FOR SELECT TO jas_si_agent_task_owner USING(true);
        CREATE POLICY install_taskowner_read ON public.jas_si_github_app_installations FOR SELECT TO jas_si_agent_task_owner USING(true);
        CREATE POLICY repo_taskowner_read ON public.jas_si_github_app_installation_repositories FOR SELECT TO jas_si_agent_task_owner USING(true);
        """
        migration = MIGRATION.read_text(encoding="utf-8")
        with psycopg.connect(dsn) as admin:
            admin.execute(schema)
            admin.commit()
            with admin.transaction():
                admin.execute(migration)
            with admin.transaction():
                admin.execute(migration)  # Idempotency/replay check.
            # Model Neon-managed ownership: cloud_admin grants neondb_owner
            # ADMIN OPTION on the newly-created capability role, without SET/INHERIT.
            admin.execute("CREATE ROLE cloud_admin SUPERUSER LOGIN PASSWORD 'cloud-admin-test-secret'")
            admin.execute("CREATE ROLE neondb_owner NOLOGIN")
            admin.commit()
            from psycopg.conninfo import make_conninfo
            cloud_admin_dsn = make_conninfo(dsn, user="cloud_admin", password="cloud-admin-test-secret")
            with psycopg.connect(cloud_admin_dsn) as cloud_admin:
                cloud_admin.execute("GRANT jas_si_agent_capability_broker TO neondb_owner WITH ADMIN TRUE, INHERIT FALSE, SET FALSE")
            managed_membership = admin.execute("""
                SELECT member.rolname, grantor.rolsuper, m.admin_option,
                       m.inherit_option, m.set_option
                FROM pg_auth_members m
                JOIN pg_roles member ON member.oid=m.member
                JOIN pg_roles grantor ON grantor.oid=m.grantor
                JOIN pg_roles granted ON granted.oid=m.roleid
                WHERE granted.rolname='jas_si_agent_capability_broker'
                  AND member.rolname='neondb_owner'
            """).fetchone()
            self.assertEqual(managed_membership, ("neondb_owner", True, True, False, False))
            admin.commit()
            with admin.transaction():
                admin.execute(migration)  # Must accept only the exact Neon owner membership.
            admin.execute("CREATE ROLE jas_si_agent_broker_login_test LOGIN PASSWORD 'broker-test-secret' NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS")
            admin.execute("GRANT jas_si_agent_capability_broker TO jas_si_agent_broker_login_test WITH ADMIN FALSE, INHERIT FALSE, SET TRUE")
            with admin.transaction():
                admin.execute(migration)  # Recheck after approved-style login membership exists.
            self.assertTrue(admin.execute("SELECT has_table_privilege('jas_si_agent_task_owner','public.jas_si_tenants','SELECT')").fetchone()[0])
            admin.execute("INSERT INTO public.jas_si_tenants VALUES ('11111111-1111-4111-8111-111111111111','active')")
            admin.execute("INSERT INTO public.jas_si_agent_tasks VALUES ('22222222-2222-4222-8222-222222222222','11111111-1111-4111-8111-111111111111','github.read_repository','running',%s,'jas_si_agent_worker_login',now()+interval '5 minutes',4,NULL,NULL,NULL,0)", ('{"repository":"octo/repo","commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","paths":["README.md"]}',))
            admin.execute("INSERT INTO public.jas_si_agent_tasks VALUES ('33333333-3333-4333-8333-333333333333','11111111-1111-4111-8111-111111111111','github.read_repository','awaiting_verification',%s,NULL,NULL,0,'jas_si_agent_verifier_login','44444444-4444-4444-8444-444444444444',now()+interval '5 minutes',1)", ('{"repository":"octo/repo","commit_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","paths":["src/main.py"]}',))
            admin.execute("INSERT INTO public.jas_si_github_app_installations VALUES (123,'11111111-1111-4111-8111-111111111111','active',now())")
            admin.execute("INSERT INTO public.jas_si_github_app_installation_repositories VALUES (123,'11111111-1111-4111-8111-111111111111','octo/repo','active',now())")
            admin.commit()
            admin.execute("GRANT USAGE ON SCHEMA public TO jas_si_agent_capability_broker")
            admin.execute("GRANT SELECT ON public.jas_si_agent_tasks,public.jas_si_github_app_installations,public.jas_si_github_app_installation_repositories TO jas_si_agent_task_owner")
            admin.commit()
            # The routine is SECURITY DEFINER, owned by the task owner, and the
            # task-owner policies make the minimal persisted lookup available.
        from psycopg.conninfo import make_conninfo
        broker_dsn = make_conninfo(dsn, user="jas_si_agent_broker_login_test", password="broker-test-secret")
        with psycopg.connect(broker_dsn, autocommit=True) as broker:
            # Login role has SET-only membership: explicitly enter the Broker
            # capability role; inherited execution is intentionally forbidden.
            broker.execute("SET ROLE jas_si_agent_capability_broker")
            # The DB session is the Broker; persisted lease/claim principals
            # remain the distinct Worker and Verifier login identities.
            self.assertEqual(
                broker.execute("SELECT session_user").fetchone()[0],
                "jas_si_agent_broker_login_test",
            )
            row = broker.execute(
                "SELECT task_id,tenant_id,installation_id,repository_full_name,capability_role,lease_fence,verifier_claim_token,expires_at,commit_sha,repository_paths FROM public.jas_si_github_task_capability_resolve(%s,%s,'worker',4,NULL)",
                ("22222222-2222-4222-8222-222222222222","jas_si_agent_worker_login"),
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[2],123)
            self.assertEqual(row[3],"octo/repo")
            self.assertIsNone(row[6])
            self.assertEqual(row[8],"a"*40)
            wrong_worker_principal = broker.execute(
                "SELECT 1 FROM public.jas_si_github_task_capability_resolve(%s,%s,'worker',4,NULL)",
                ("22222222-2222-4222-8222-222222222222","jas_si_agent_verifier_login"),
            ).fetchone()
            self.assertIsNone(wrong_worker_principal)
            stale = broker.execute(
                "SELECT 1 FROM public.jas_si_github_task_capability_resolve(%s,%s,'worker',3,NULL)",
                ("22222222-2222-4222-8222-222222222222","jas_si_agent_worker_login"),
            ).fetchone()
            self.assertIsNone(stale)
            verified = broker.execute(
                "SELECT verifier_claim_token,commit_sha,repository_paths FROM public.jas_si_github_task_capability_resolve(%s,%s,'verifier',NULL,%s)",
                ("33333333-3333-4333-8333-333333333333","jas_si_agent_verifier_login","44444444-4444-4444-8444-444444444444"),
            ).fetchone()
            self.assertIsNotNone(verified)
            self.assertEqual(str(verified[0]),"44444444-4444-4444-8444-444444444444")
            self.assertEqual(verified[1],"b"*40)
            wrong_verifier_principal = broker.execute(
                "SELECT 1 FROM public.jas_si_github_task_capability_resolve(%s,%s,'verifier',NULL,%s)",
                ("33333333-3333-4333-8333-333333333333","jas_si_agent_worker_login","44444444-4444-4444-8444-444444444444"),
            ).fetchone()
            self.assertIsNone(wrong_verifier_principal)
            invalid_claim = broker.execute(
                "SELECT 1 FROM public.jas_si_github_task_capability_resolve(%s,%s,'verifier',NULL,%s)",
                ("33333333-3333-4333-8333-333333333333","jas_si_agent_verifier_login","55555555-5555-4555-8555-555555555555"),
            ).fetchone()
            self.assertIsNone(invalid_claim)

            worker_lookup = (
                "SELECT 1 FROM public.jas_si_github_task_capability_resolve(%s,%s,'worker',4,NULL)",
                ("22222222-2222-4222-8222-222222222222","jas_si_agent_worker_login"),
            )

            def assert_worker_denied(update_sql: str, reset_sql: str) -> None:
                with psycopg.connect(dsn) as fixture:
                    fixture.execute(update_sql)
                    fixture.commit()
                try:
                    self.assertIsNone(broker.execute(*worker_lookup).fetchone())
                finally:
                    with psycopg.connect(dsn) as fixture:
                        fixture.execute(reset_sql)
                        fixture.commit()

            # Tenant, installation, and repository trust must all be active
            # and independently verified before a task capability is returned.
            assert_worker_denied(
                "UPDATE public.jas_si_tenants SET status='suspended' WHERE tenant_id='11111111-1111-4111-8111-111111111111'",
                "UPDATE public.jas_si_tenants SET status='active' WHERE tenant_id='11111111-1111-4111-8111-111111111111'",
            )
            assert_worker_denied(
                "UPDATE public.jas_si_github_app_installations SET status='suspended' WHERE installation_id=123",
                "UPDATE public.jas_si_github_app_installations SET status='active' WHERE installation_id=123",
            )
            assert_worker_denied(
                "UPDATE public.jas_si_github_app_installations SET verified_at=NULL WHERE installation_id=123",
                "UPDATE public.jas_si_github_app_installations SET verified_at=now() WHERE installation_id=123",
            )
            assert_worker_denied(
                "UPDATE public.jas_si_github_app_installation_repositories SET status='suspended' WHERE installation_id=123",
                "UPDATE public.jas_si_github_app_installation_repositories SET status='active' WHERE installation_id=123",
            )
            assert_worker_denied(
                "UPDATE public.jas_si_github_app_installation_repositories SET verified_at=NULL WHERE installation_id=123",
                "UPDATE public.jas_si_github_app_installation_repositories SET verified_at=now() WHERE installation_id=123",
            )
            assert_worker_denied(
                "UPDATE public.jas_si_github_app_installation_repositories SET repository_full_name='octo/other' WHERE installation_id=123",
                "UPDATE public.jas_si_github_app_installation_repositories SET repository_full_name='octo/repo' WHERE installation_id=123",
            )

            # Task type/state, lease expiry, commit identity, and bounded paths
            # are all part of the capability predicate.
            assert_worker_denied(
                "UPDATE public.jas_si_agent_tasks SET task_type='github.write_repository' WHERE task_id='22222222-2222-4222-8222-222222222222'",
                "UPDATE public.jas_si_agent_tasks SET task_type='github.read_repository' WHERE task_id='22222222-2222-4222-8222-222222222222'",
            )
            assert_worker_denied(
                "UPDATE public.jas_si_agent_tasks SET status='queued' WHERE task_id='22222222-2222-4222-8222-222222222222'",
                "UPDATE public.jas_si_agent_tasks SET status='running' WHERE task_id='22222222-2222-4222-8222-222222222222'",
            )
            assert_worker_denied(
                "UPDATE public.jas_si_agent_tasks SET lease_expires_at=now()-interval '1 second' WHERE task_id='22222222-2222-4222-8222-222222222222'",
                "UPDATE public.jas_si_agent_tasks SET lease_expires_at=now()+interval '5 minutes' WHERE task_id='22222222-2222-4222-8222-222222222222'",
            )
            assert_worker_denied(
                "UPDATE public.jas_si_agent_tasks SET input_payload=jsonb_set(input_payload,'{commit_sha}','\"not-a-sha\"'::jsonb) WHERE task_id='22222222-2222-4222-8222-222222222222'",
                "UPDATE public.jas_si_agent_tasks SET input_payload=jsonb_set(input_payload,'{commit_sha}','\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"'::jsonb) WHERE task_id='22222222-2222-4222-8222-222222222222'",
            )
            assert_worker_denied(
                "UPDATE public.jas_si_agent_tasks SET input_payload=jsonb_set(input_payload,'{paths}','[]'::jsonb) WHERE task_id='22222222-2222-4222-8222-222222222222'",
                "UPDATE public.jas_si_agent_tasks SET input_payload=jsonb_set(input_payload,'{paths}','[\"README.md\"]'::jsonb) WHERE task_id='22222222-2222-4222-8222-222222222222'",
            )
            assert_worker_denied(
                "UPDATE public.jas_si_agent_tasks SET input_payload=jsonb_set(input_payload,'{paths}','[\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\",\"h\",\"i\",\"j\",\"k\"]'::jsonb) WHERE task_id='22222222-2222-4222-8222-222222222222'",
                "UPDATE public.jas_si_agent_tasks SET input_payload=jsonb_set(input_payload,'{paths}','[\"README.md\"]'::jsonb) WHERE task_id='22222222-2222-4222-8222-222222222222'",
            )

            with self.assertRaises(psycopg.errors.InvalidParameterValue):
                broker.execute(
                    "SELECT 1 FROM public.jas_si_github_task_capability_resolve(%s,%s,'worker',NULL,NULL)",
                    ("22222222-2222-4222-8222-222222222222","jas_si_agent_worker_login"),
                ).fetchone()
            with self.assertRaises(psycopg.errors.InvalidParameterValue):
                broker.execute(
                    "SELECT 1 FROM public.jas_si_github_task_capability_resolve(%s,%s,'operator',4,NULL)",
                    ("22222222-2222-4222-8222-222222222222","jas_si_agent_worker_login"),
                ).fetchone()

            # Verifier claims expire independently of Worker leases.
            with psycopg.connect(dsn) as fixture:
                fixture.execute(
                    "UPDATE public.jas_si_agent_tasks SET verifier_lease_expires_at=now()-interval '1 second' "
                    "WHERE task_id='33333333-3333-4333-8333-333333333333'"
                )
                fixture.commit()
            try:
                expired_claim = broker.execute(
                    "SELECT 1 FROM public.jas_si_github_task_capability_resolve(%s,%s,'verifier',NULL,%s)",
                    ("33333333-3333-4333-8333-333333333333","jas_si_agent_verifier_login",
                     "44444444-4444-4444-8444-444444444444"),
                ).fetchone()
                self.assertIsNone(expired_claim)
            finally:
                with psycopg.connect(dsn) as fixture:
                    fixture.execute(
                        "UPDATE public.jas_si_agent_tasks SET verifier_lease_expires_at=now()+interval '5 minutes' "
                        "WHERE task_id='33333333-3333-4333-8333-333333333333'"
                    )
                    fixture.commit()
        worker_dsn = make_conninfo(dsn, user="jas_si_agent_worker_login", password="worker-test-secret")
        with psycopg.connect(worker_dsn, autocommit=True) as worker:
            worker.execute("SET ROLE jas_si_agent_worker")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                worker.execute(
                    "SELECT * FROM public.jas_si_github_task_capability_resolve(%s,%s,'worker',4,NULL)",
                    ("22222222-2222-4222-8222-222222222222","jas_si_agent_worker_login"),
                ).fetchone()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                worker.execute(
                    "SELECT * FROM public.jas_si_github_installation_binding_resolve(%s,%s)",
                    ("11111111-1111-4111-8111-111111111111","octo/repo"),
                ).fetchone()
        verifier_dsn = make_conninfo(dsn, user="jas_si_agent_verifier_login", password="verifier-test-secret")
        with psycopg.connect(verifier_dsn, autocommit=True) as verifier:
            verifier.execute("SET ROLE jas_si_agent_verifier")
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                verifier.execute(
                    "SELECT * FROM public.jas_si_github_task_capability_resolve(%s,%s,'verifier',NULL,%s)",
                    ("33333333-3333-4333-8333-333333333333","jas_si_agent_verifier_login",
                     "44444444-4444-4444-8444-444444444444"),
                ).fetchone()
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                verifier.execute(
                    "SELECT * FROM public.jas_si_github_installation_binding_resolve(%s,%s)",
                    ("11111111-1111-4111-8111-111111111111","octo/repo"),
                ).fetchone()
        with psycopg.connect(dsn) as admin:
            self.assertFalse(admin.execute("SELECT has_function_privilege('jas_si_agent_worker','public.jas_si_github_task_capability_resolve(uuid,name,text,bigint,uuid)','EXECUTE')").fetchone()[0])
            self.assertFalse(admin.execute("SELECT has_function_privilege('jas_si_agent_verifier','public.jas_si_github_task_capability_resolve(uuid,name,text,bigint,uuid)','EXECUTE')").fetchone()[0])
            self.assertFalse(admin.execute("SELECT has_function_privilege('jas_si_agent_worker','public.jas_si_github_installation_binding_resolve(uuid,text)','EXECUTE')").fetchone()[0])
            self.assertFalse(admin.execute("SELECT has_function_privilege('jas_si_agent_verifier','public.jas_si_github_installation_binding_resolve(uuid,text)','EXECUTE')").fetchone()[0])
            self.assertFalse(admin.execute("SELECT has_function_privilege('jas_si_agent_capability_broker','public.jas_si_github_installation_binding_resolve(uuid,text)','EXECUTE')").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
