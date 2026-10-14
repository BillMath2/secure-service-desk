BEGIN;
ALTER TABLE service_desk.read_attempt DROP CONSTRAINT read_attempt_service_check;
ALTER TABLE service_desk.read_attempt ADD CHECK(service IN ('knowledge','tickets','access','gateway'));
CREATE OR REPLACE FUNCTION service_desk.reserve_read_attempt(
    p_id uuid, p_task uuid, p_issuer text, p_subject text, p_service text, p_tool text, p_hash text
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE t service_desk.read_task; reason text := 'ALLOW';
BEGIN
    IF p_service NOT IN ('knowledge', 'tickets', 'access', 'gateway') OR NOT (
      pg_has_role(session_user, 'desk_gateway', 'member') OR
      (p_service = 'knowledge' AND pg_has_role(session_user, 'desk_knowledge', 'member')) OR
      (p_service = 'tickets' AND pg_has_role(session_user, 'desk_tickets', 'member')) OR (p_service = 'access' AND pg_has_role(session_user, 'desk_access', 'member'))
    ) THEN RETURN 'SERVICE_DENIED'; END IF;
    SELECT * INTO t FROM service_desk.read_task WHERE id = p_task FOR UPDATE;
    IF NOT FOUND OR t.issuer IS DISTINCT FROM p_issuer OR t.subject IS DISTINCT FROM p_subject
      THEN RETURN 'TASK_DENIED'; END IF;
    IF NOT t.active THEN reason := 'TASK_DENIED';
    ELSIF t.deadline <= clock_timestamp() THEN reason := 'TASK_EXPIRED';
    ELSIF t.policy_version <> (SELECT version FROM service_desk.read_policy)
      THEN reason := 'POLICY_STALE';
    ELSIF t.used_calls >= t.max_calls THEN reason := 'BUDGET_EXHAUSTED';
    ELSE
      UPDATE service_desk.read_task SET used_calls = used_calls + 1 WHERE id = p_task;
      INSERT INTO service_desk.read_attempt VALUES
        (p_id, p_task, p_service, p_tool, p_hash, 'reserved', clock_timestamp());
    END IF;
    INSERT INTO service_desk.read_audit(task_id, attempt_id, correlation_id, operation, reason)
      VALUES(p_task, CASE WHEN reason = 'ALLOW' THEN p_id END, t.correlation_id, p_tool,
             CASE WHEN reason = 'ALLOW' THEN 'RESERVED' ELSE reason END);
    RETURN reason;
END $$;

CREATE OR REPLACE FUNCTION service_desk.consume_read_attempt(
    p_id uuid, p_task uuid, p_issuer text, p_subject text, p_service text, p_tool text, p_hash text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE t service_desk.read_task; a service_desk.read_attempt;
BEGIN
    IF NOT ((p_service = 'knowledge' AND pg_has_role(session_user, 'desk_knowledge', 'member')) OR
            (p_service = 'tickets' AND pg_has_role(session_user, 'desk_tickets', 'member')) OR (p_service = 'access' AND pg_has_role(session_user, 'desk_access', 'member')))
      THEN RETURN NULL; END IF;
    SELECT * INTO t FROM service_desk.read_task WHERE id = p_task FOR UPDATE;
    IF NOT FOUND OR t.issuer IS DISTINCT FROM p_issuer OR t.subject IS DISTINCT FROM p_subject
       OR NOT t.active
       OR t.deadline <= clock_timestamp()
       OR t.policy_version <> (SELECT version FROM service_desk.read_policy)
      THEN RETURN NULL; END IF;
    SELECT * INTO a FROM service_desk.read_attempt WHERE id = p_id FOR UPDATE;
    IF NOT FOUND OR a.task_id IS DISTINCT FROM p_task OR a.service IS DISTINCT FROM p_service
       OR a.tool IS DISTINCT FROM p_tool OR a.arguments_hash IS DISTINCT FROM p_hash
       OR a.state <> 'reserved' THEN RETURN NULL; END IF;
    UPDATE service_desk.read_attempt SET state = 'consumed' WHERE id = p_id;
    RETURN to_jsonb(t);
END $$;

CREATE OR REPLACE FUNCTION service_desk.finish_read_attempt(p_id uuid, p_reason text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE a service_desk.read_attempt; t service_desk.read_task;
BEGIN
    IF p_reason NOT IN ('ALLOW', 'TOOL_DENIED', 'SCHEMA_DENIED', 'CATALOG_DENIED',
      'SCOPE_DENIED', 'RESOURCE_DENIED', 'TASK_DENIED', 'TASK_EXPIRED', 'POLICY_STALE',
      'OUTPUT_LIMIT', 'SERVICE_ERROR', 'TIMEOUT', 'POLICY_DENIED', 'OUTPUT_DENIED', 'BUDGET_EXHAUSTED') THEN RETURN false; END IF;
    SELECT * INTO a FROM service_desk.read_attempt WHERE id = p_id FOR UPDATE;
    IF NOT FOUND OR a.state = 'finished' OR NOT (
      (a.service = 'knowledge' AND pg_has_role(session_user, 'desk_knowledge', 'member')) OR
      (a.service = 'tickets' AND pg_has_role(session_user, 'desk_tickets', 'member')) OR (a.service = 'access' AND pg_has_role(session_user, 'desk_access', 'member')) OR
      (p_reason <> 'ALLOW' AND pg_has_role(session_user, 'desk_gateway', 'member'))
    ) THEN RETURN false; END IF;
    SELECT * INTO t FROM service_desk.read_task WHERE id = a.task_id;
    IF p_reason = 'ALLOW' AND (a.state <> 'consumed' OR NOT t.active
       OR t.policy_version <> (SELECT version FROM service_desk.read_policy)
       OR t.deadline <= clock_timestamp()) THEN p_reason := 'TASK_DENIED'; END IF;
    UPDATE service_desk.read_attempt SET state = 'finished' WHERE id = p_id;
    INSERT INTO service_desk.read_audit(task_id, attempt_id, correlation_id, operation, reason)
      VALUES(t.id, a.id, t.correlation_id, a.tool, p_reason);
    RETURN p_reason = 'ALLOW';
END $$;

CREATE OR REPLACE FUNCTION service_desk.create_read_task(
    p_id uuid, p_correlation uuid, p_issuer text, p_subject text, p_ticket text, p_audience text
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE actor text; target text; readers text[]; policy service_desk.read_policy;
BEGIN
    SELECT b.principal_id INTO actor FROM service_desk.identity_binding b
      JOIN service_desk.principal p ON p.id = b.principal_id AND p.kind = 'human'
      WHERE b.issuer = p_issuer AND b.subject = p_subject;
    SELECT t.requester INTO target FROM service_desk.ticket t
      JOIN service_desk.ticket_reader r ON r.ticket_id = t.id AND r.principal_id = actor
      WHERE t.id = p_ticket;
    IF actor IS NULL OR target IS NULL OR p_audience IS NULL
       OR p_audience NOT IN ('self', 'requester') THEN
        RETURN false;
    END IF;
    readers := ARRAY[CASE WHEN p_audience = 'self' THEN actor ELSE target END];
    SELECT * INTO STRICT policy FROM service_desk.read_policy;
    INSERT INTO service_desk.read_task
      (id, correlation_id, issuer, subject, principal_id, client_id, ticket_id, recipients,
       capabilities, policy_version, deadline, max_calls, max_bytes)
      VALUES (p_id, p_correlation, p_issuer, p_subject, actor, 'gateway', p_ticket, readers,
       ARRAY['read_document', 'search_documents', 'read_ticket'] || CASE WHEN p_audience='self' THEN ARRAY['check_access','propose_access_change'] ELSE ARRAY[]::text[] END, policy.version,
       clock_timestamp() + make_interval(secs => policy.timeout_seconds),
       policy.max_calls, policy.max_bytes);
    RETURN true;
END $$;
CREATE FUNCTION service_desk.access_model_draft(i text,s text,task uuid,g text,seconds integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE t service_desk.read_task;
BEGIN
 SELECT * INTO t FROM service_desk.read_task WHERE id=task;
 IF t.id IS NULL OR t.principal_id IS DISTINCT FROM service_desk.access_actor(i,s)
  OR NOT ('propose_access_change'=ANY(t.capabilities)) OR t.draft_audience IS NOT NULL THEN
  RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
 RETURN service_desk.access_draft(i,s,t.ticket_id,g,seconds,
  'Model-proposed access request. Verify the original ticket; no approval has been granted.',task);
END $$;
CREATE FUNCTION service_desk.access_model_check(i text,s text,task uuid,g text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE t service_desk.read_task; b text;
BEGIN
 SELECT * INTO t FROM service_desk.read_task WHERE id=task;
 IF t.id IS NULL OR t.principal_id IS DISTINCT FROM service_desk.access_actor(i,s)
  OR NOT t.active OR t.deadline<=clock_timestamp() OR t.policy_version<>(SELECT version FROM service_desk.read_policy)
  OR t.recipients<>ARRAY[t.principal_id] OR NOT ('check_access'=ANY(t.capabilities)) THEN
  RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
 SELECT requester INTO b FROM service_desk.ticket WHERE id=t.ticket_id;
 RETURN service_desk.access_check(i,s,b,g);
END $$;
CREATE FUNCTION service_desk.access_inbox(i text,s text) RETURNS jsonb LANGUAGE sql
SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
 SELECT jsonb_build_object('reason','ALLOW','requests',coalesce(jsonb_agg(x),'[]'::jsonb)) FROM (
  SELECT r.id AS request_id,r.ticket_id,r.resource_id,st.state FROM service_desk.access_request r
  JOIN service_desk.access_state st ON st.request_id=r.id
  WHERE service_desk.access_actor(i,s)=ANY(ARRAY[r.triggerer,r.submitter,r.manager_id,r.owner_id])
  AND EXISTS(SELECT 1 FROM service_desk.ticket_reader tr WHERE tr.ticket_id=r.ticket_id AND tr.principal_id=service_desk.access_actor(i,s))
  ORDER BY r.created_at DESC LIMIT 40) x
$$;
REVOKE ALL ON FUNCTION service_desk.access_model_draft(text,text,uuid,text,integer),service_desk.access_model_check(text,text,uuid,text),service_desk.access_inbox(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.access_model_draft(text,text,uuid,text,integer),service_desk.access_model_check(text,text,uuid,text) TO desk_access;
GRANT EXECUTE ON FUNCTION service_desk.access_inbox(text,text) TO desk_workflow;
GRANT EXECUTE ON FUNCTION service_desk.reserve_read_attempt(uuid,uuid,text,text,text,text,text),service_desk.consume_read_attempt(uuid,uuid,text,text,text,text,text),service_desk.finish_read_attempt(uuid,text) TO desk_access;
INSERT INTO service_desk.schema_version VALUES(13,clock_timestamp());
COMMIT;
