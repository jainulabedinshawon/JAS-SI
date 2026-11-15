-- Add the durable agent-task submission operation to the existing
-- API-key-bound usage reservation routine without changing prior migrations.
-- The operation is bound to the existing agent:tasks:write API-key scope.
-- This is an additive function-definition update; no data or privileges change.

DO $migration$
DECLARE
    v_definition text;
    v_old text := $old$
    IF p_operation NOT IN ('authorization.evaluate','outcome.submit','github.evidence.verify')
       OR (p_operation='authorization.evaluate' AND p_required_scope<>'authorization:check')
       OR (p_operation='outcome.submit' AND p_required_scope<>'outcomes:submit')
       OR (p_operation='github.evidence.verify' AND p_required_scope<>'github:evidence:verify') THEN
$old$;
    v_new text := $new$
    IF p_operation NOT IN ('authorization.evaluate','outcome.submit','github.evidence.verify','agent.task.submit')
       OR (p_operation='authorization.evaluate' AND p_required_scope<>'authorization:check')
       OR (p_operation='outcome.submit' AND p_required_scope<>'outcomes:submit')
       OR (p_operation='github.evidence.verify' AND p_required_scope<>'github:evidence:verify')
       OR (p_operation='agent.task.submit' AND p_required_scope<>'agent:tasks:write') THEN
$new$;
    v_occurrences integer;
BEGIN
    SELECT pg_catalog.pg_get_functiondef(
        'public.jas_si_api_key_usage_reserve(uuid,bytea,text,text,text,text,text,bigint,bigint)'::regprocedure
    ) INTO v_definition;

    IF v_definition IS NULL THEN
        RAISE EXCEPTION 'API-key usage reservation routine is missing';
    END IF;

    v_occurrences := (
        pg_catalog.length(v_definition)
        - pg_catalog.length(pg_catalog.replace(v_definition, v_old, ''))
    ) / pg_catalog.length(v_old);

    IF v_occurrences = 0 THEN
        -- Idempotent replay is allowed only when the desired scope binding exists.
        IF pg_catalog.position('agent.task.submit' IN v_definition) > 0
           AND pg_catalog.position('agent:tasks:write' IN v_definition) > 0 THEN
            RETURN;
        END IF;
        RAISE EXCEPTION 'Unexpected API-key usage reservation definition; refusing rewrite';
    ELSIF v_occurrences <> 1 THEN
        RAISE EXCEPTION 'Ambiguous API-key usage reservation definition; refusing rewrite';
    END IF;

    v_definition := pg_catalog.replace(v_definition, v_old, v_new);
    EXECUTE v_definition;
END
$migration$;
