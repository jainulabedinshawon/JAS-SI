-- Align PostgreSQL-enforced GitHub login boundaries with the application validators.
-- GitHub account and repository-owner logins cannot contain consecutive hyphens.
DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE conrelid='public.jas_si_github_installation_claims'::regclass
           AND conname='jas_si_github_claim_user_login_no_double_hyphen'
    ) THEN
        ALTER TABLE public.jas_si_github_installation_claims
            ADD CONSTRAINT jas_si_github_claim_user_login_no_double_hyphen
            CHECK (github_user_login !~ '--');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE conrelid='public.jas_si_github_installation_claims'::regclass
           AND conname='jas_si_github_claim_account_login_no_double_hyphen'
    ) THEN
        ALTER TABLE public.jas_si_github_installation_claims
            ADD CONSTRAINT jas_si_github_claim_account_login_no_double_hyphen
            CHECK (github_account_login !~ '--');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE conrelid='public.jas_si_github_app_installations'::regclass
           AND conname='jas_si_github_installation_login_no_double_hyphen'
    ) THEN
        ALTER TABLE public.jas_si_github_app_installations
            ADD CONSTRAINT jas_si_github_installation_login_no_double_hyphen
            CHECK (account_login !~ '--');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE conrelid='public.jas_si_github_app_installation_repositories'::regclass
           AND conname='jas_si_github_repository_owner_no_double_hyphen'
    ) THEN
        ALTER TABLE public.jas_si_github_app_installation_repositories
            ADD CONSTRAINT jas_si_github_repository_owner_no_double_hyphen
            CHECK (pg_catalog.split_part(repository_full_name, '/', 1) !~ '--');
    END IF;
END
$migration$;
