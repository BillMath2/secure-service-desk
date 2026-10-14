-- First Phase 3 slice: fresh requester context, no ticket writes or confirmations.
BEGIN;
CREATE TABLE service_desk.ticket_reply_participant (
  ticket_id text NOT NULL REFERENCES service_desk.ticket(id),
  principal_id text NOT NULL REFERENCES service_desk.principal(id),
  PRIMARY KEY(ticket_id, principal_id)
);
CREATE TABLE service_desk.requester_run (
  task_id uuid PRIMARY KEY REFERENCES service_desk.read_task(id),
  manifest jsonb
);
REVOKE ALL ON service_desk.ticket_reply_participant, service_desk.requester_run FROM PUBLIC;

-- Participation is managed by the trusted fixture/admin plane, never by a model or browser.
CREATE FUNCTION service_desk.requester_recipients(p_ticket text) RETURNS text[]
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
  SELECT array_agg(id ORDER BY id) FROM (
    SELECT requester AS id FROM service_desk.ticket WHERE id = p_ticket
    UNION SELECT principal_id FROM service_desk.ticket_reply_participant WHERE ticket_id = p_ticket
  ) AS recipients
$$;

CREATE FUNCTION service_desk.requester_manifest(t service_desk.read_task) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE viewers text[] := t.recipients || t.principal_id; result jsonb;
BEGIN
  IF t.recipients IS DISTINCT FROM service_desk.requester_recipients(t.ticket_id)
    OR NOT EXISTS (SELECT 1 FROM service_desk.identity_binding b
      WHERE b.issuer=t.issuer AND b.subject=t.subject AND b.principal_id=t.principal_id)
    OR EXISTS (SELECT 1 FROM unnest(viewers) AS v(id) WHERE
      NOT EXISTS (SELECT 1 FROM service_desk.principal p WHERE p.id=v.id AND p.kind='human')
      OR NOT EXISTS (SELECT 1 FROM service_desk.ticket_reader r
        WHERE r.ticket_id=t.ticket_id AND r.principal_id=v.id)
      OR NOT EXISTS (SELECT 1 FROM service_desk.document_reader r
        WHERE r.document_id='doc-public' AND r.principal_id=v.id))
    THEN RETURN NULL; END IF;
  -- Fixed initial recipe: requester-visible ticket/history and the public support guide.
  -- Hash every content field, even if an editor forgot to increment the source version.
  SELECT jsonb_agg(item ORDER BY item->>'kind', item->>'id') INTO result FROM (
    SELECT jsonb_build_object('kind','ticket','id',x.id,'version',x.version,
      'body_sha256',encode(sha256(convert_to(x.body,'UTF8')),'hex')) AS item
      FROM service_desk.ticket x WHERE x.id=t.ticket_id
    UNION ALL
    SELECT jsonb_build_object('kind','document','id',d.id,'version',d.version,
      'body_sha256',encode(sha256(convert_to(d.body,'UTF8')),'hex'),
      'title_sha256',encode(sha256(convert_to(d.title,'UTF8')),'hex'))
      FROM service_desk.document d WHERE d.id='doc-public'
    UNION ALL
    SELECT jsonb_build_object('kind','comment','id',c.id,'visibility',c.visibility,
      'body_sha256',encode(sha256(convert_to(c.body,'UTF8')),'hex'))
      FROM service_desk.ticket_comment c WHERE c.ticket_id=t.ticket_id
      AND c.visibility='requester' AND NOT EXISTS (
        SELECT 1 FROM unnest(viewers) AS v(id) WHERE NOT EXISTS (
          SELECT 1 FROM service_desk.comment_reader r
          WHERE r.comment_id=c.id AND r.principal_id=v.id))
  ) AS items;
  RETURN result;
END $$;

CREATE FUNCTION service_desk.create_requester_task(
  p_id uuid, p_correlation uuid, p_issuer text, p_subject text, p_ticket text
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE t service_desk.read_task;
BEGIN
  IF NOT service_desk.create_read_task(p_id,p_correlation,p_issuer,p_subject,p_ticket,'requester')
    THEN RETURN false; END IF;
  UPDATE service_desk.read_task SET recipients=service_desk.requester_recipients(p_ticket)
    WHERE id=p_id RETURNING * INTO t;
  IF service_desk.requester_manifest(t) IS NULL THEN
    DELETE FROM service_desk.read_task WHERE id=p_id;
    RETURN false;
  END IF;
  INSERT INTO service_desk.requester_run(task_id) VALUES(p_id);
  RETURN true;
END $$;

-- Even when the caller is also the requester, chat cannot claim a draft task.
ALTER FUNCTION service_desk.agent_action(uuid,text,text,text,integer,jsonb) RENAME TO chat_action;
REVOKE ALL ON FUNCTION service_desk.chat_action(uuid,text,text,text,integer,jsonb)
  FROM PUBLIC, desk_task_creator;
CREATE FUNCTION service_desk.agent_action(
  p_task uuid, p_issuer text, p_subject text, p_action text, p_tokens integer,
  p_sources jsonb DEFAULT '[]'::jsonb
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM service_desk.requester_run WHERE task_id=p_task)
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  RETURN service_desk.chat_action(p_task,p_issuer,p_subject,p_action,p_tokens,p_sources);
END $$;

CREATE FUNCTION service_desk.requester_action(
  p_task uuid, p_issuer text, p_subject text, p_action text, p_tokens integer,
  p_sources jsonb DEFAULT '[]'::jsonb
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE t service_desk.read_task; stored jsonb; expected jsonb; reason text := 'ALLOW';
BEGIN
  SELECT * INTO t FROM service_desk.read_task WHERE id=p_task FOR UPDATE;
  IF NOT FOUND OR t.issuer IS DISTINCT FROM p_issuer OR t.subject IS DISTINCT FROM p_subject
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  SELECT manifest INTO stored FROM service_desk.requester_run WHERE task_id=p_task;
  IF NOT FOUND THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  expected := service_desk.requester_manifest(t);
  IF p_action='stop' AND t.agent_state='running' THEN
    UPDATE service_desk.read_task SET active=false, agent_state='stopped' WHERE id=p_task;
  ELSIF NOT t.active THEN reason := 'TASK_DENIED';
  ELSIF t.deadline <= clock_timestamp() THEN reason := 'TASK_EXPIRED';
  ELSIF t.policy_version <> (SELECT version FROM service_desk.read_policy)
    THEN reason := 'POLICY_STALE';
  ELSIF expected IS NULL THEN reason := 'RESOURCE_DENIED';
  ELSIF p_action='claim' AND t.agent_state='pending' THEN
    UPDATE service_desk.read_task SET agent_state='running' WHERE id=p_task;
  ELSIF p_action IN ('reserve','finish') AND p_sources IS DISTINCT FROM expected
    THEN reason := 'RESOURCE_DENIED';
  ELSIF p_action='reserve' AND t.agent_state='running' AND t.model_calls=0 THEN
    IF p_tokens IS NULL OR p_tokens < 1 OR p_tokens > 16000 THEN reason := 'BUDGET_EXHAUSTED';
    ELSE
      UPDATE service_desk.read_task SET model_tokens=p_tokens, model_calls=1 WHERE id=p_task;
      UPDATE service_desk.requester_run SET manifest=p_sources WHERE task_id=p_task;
    END IF;
  ELSIF p_action='finish' AND t.agent_state='running' AND t.model_calls=1
    AND stored IS NOT DISTINCT FROM p_sources THEN
    UPDATE service_desk.read_task SET active=false, agent_state='completed' WHERE id=p_task;
  ELSE reason := 'TASK_DENIED'; END IF;
  INSERT INTO service_desk.read_audit(task_id,correlation_id,operation,reason)
    VALUES(t.id,t.correlation_id,CASE WHEN p_action IN ('claim','reserve','finish','stop')
      THEN 'requester_' || p_action ELSE 'requester_denied' END,reason);
  RETURN jsonb_build_object('reason',reason,'context',to_jsonb(t));
END $$;

REVOKE ALL ON FUNCTION service_desk.requester_recipients(text),
  service_desk.requester_manifest(service_desk.read_task),
  service_desk.create_requester_task(uuid,uuid,text,text,text),
  service_desk.requester_action(uuid,text,text,text,integer,jsonb),
  service_desk.agent_action(uuid,text,text,text,integer,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.create_requester_task(uuid,uuid,text,text,text),
  service_desk.requester_action(uuid,text,text,text,integer,jsonb),
  service_desk.agent_action(uuid,text,text,text,integer,jsonb) TO desk_task_creator;
INSERT INTO service_desk.schema_version(version) VALUES (5);
COMMIT;
