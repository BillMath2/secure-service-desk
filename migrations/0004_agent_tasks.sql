-- One-shot assistant runs; the application role cannot read business tables directly.
BEGIN;
ALTER TABLE service_desk.read_task
  ADD COLUMN agent_state text NOT NULL DEFAULT 'pending'
    CHECK (agent_state IN ('pending', 'running', 'completed', 'stopped')),
  ADD COLUMN model_tokens integer NOT NULL DEFAULT 0 CHECK (model_tokens BETWEEN 0 AND 16000),
  ADD COLUMN model_calls integer NOT NULL DEFAULT 0 CHECK (model_calls BETWEEN 0 AND 8);

CREATE FUNCTION service_desk.agent_sources_valid(t service_desk.read_task, p_sources jsonb)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE s jsonb;
BEGIN
  IF p_sources IS NULL OR jsonb_typeof(p_sources) <> 'array' THEN RETURN false; END IF;
  FOR s IN SELECT value FROM jsonb_array_elements(p_sources) LOOP
    IF s->>'kind' = 'document' THEN
      IF NOT EXISTS (SELECT 1 FROM service_desk.document d
        JOIN service_desk.document_reader r ON r.document_id = d.id
        WHERE d.id = s->>'id' AND d.version::text = s->>'version'
          AND r.principal_id = t.principal_id) THEN RETURN false; END IF;
    ELSIF s->>'kind' = 'ticket' THEN
      IF NOT EXISTS (SELECT 1 FROM service_desk.ticket x
        WHERE x.id = t.ticket_id AND x.id = s->>'id' AND x.version::text = s->>'version')
        THEN RETURN false; END IF;
    ELSIF s->>'kind' = 'comment' THEN
      IF NOT EXISTS (SELECT 1 FROM service_desk.ticket_comment c
        JOIN service_desk.ticket x ON x.id = c.ticket_id
        JOIN service_desk.comment_reader r ON r.comment_id = c.id
        WHERE c.id = s->>'id' AND c.ticket_id = t.ticket_id AND r.principal_id = t.principal_id
          AND (c.visibility = 'requester' OR x.requester <> t.principal_id))
        THEN RETURN false; END IF;
    ELSE RETURN false; END IF;
  END LOOP;
  RETURN true;
END $$;
REVOKE ALL ON FUNCTION service_desk.agent_sources_valid(service_desk.read_task,jsonb) FROM PUBLIC;

CREATE FUNCTION service_desk.agent_action(
  p_task uuid, p_issuer text, p_subject text, p_action text, p_tokens integer,
  p_sources jsonb DEFAULT '[]'::jsonb
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE t service_desk.read_task; reason text := 'ALLOW';
BEGIN
  SELECT * INTO t FROM service_desk.read_task WHERE id = p_task FOR UPDATE;
  IF NOT FOUND OR t.issuer IS DISTINCT FROM p_issuer OR t.subject IS DISTINCT FROM p_subject
    THEN RETURN jsonb_build_object('reason', 'TASK_DENIED'); END IF;
  -- Stop is permitted after expiry/revocation so cancellation can always close the task.
  IF p_action = 'stop' AND t.agent_state = 'running' THEN
    UPDATE service_desk.read_task SET active = false, agent_state = 'stopped' WHERE id = p_task;
  ELSIF NOT t.active OR t.recipients <> ARRAY[t.principal_id]
    THEN reason := 'TASK_DENIED';
  ELSIF t.deadline <= clock_timestamp() THEN reason := 'TASK_EXPIRED';
  ELSIF t.policy_version <> (SELECT version FROM service_desk.read_policy)
    THEN reason := 'POLICY_STALE';
  ELSIF NOT EXISTS (SELECT 1 FROM service_desk.ticket_reader r
    WHERE r.ticket_id = t.ticket_id AND r.principal_id = t.principal_id)
    OR NOT EXISTS (SELECT 1 FROM service_desk.identity_binding b
      JOIN service_desk.principal p ON p.id = b.principal_id AND p.kind = 'human'
      WHERE b.issuer = t.issuer AND b.subject = t.subject AND b.principal_id = t.principal_id)
    THEN reason := 'RESOURCE_DENIED';
  ELSIF p_action = 'claim' AND t.agent_state = 'pending' THEN
    UPDATE service_desk.read_task SET agent_state = 'running' WHERE id = p_task;
  ELSIF p_action IN ('reserve', 'finish') AND NOT service_desk.agent_sources_valid(t, p_sources)
    THEN reason := 'RESOURCE_DENIED';
  ELSIF p_action = 'reserve' AND t.agent_state = 'running' THEN
    IF p_tokens IS NULL OR p_tokens < 1 OR p_tokens > 16000
      OR t.model_tokens + p_tokens > 16000 OR t.model_calls >= 8
      THEN reason := 'BUDGET_EXHAUSTED';
    ELSE
      -- No refunds: failed/timed-out provider calls retain the entire reservation.
      UPDATE service_desk.read_task SET model_tokens = model_tokens + p_tokens,
        model_calls = model_calls + 1 WHERE id = p_task;
    END IF;
  ELSIF p_action = 'finish' AND t.agent_state = 'running' THEN
    UPDATE service_desk.read_task SET active = false, agent_state = 'completed' WHERE id = p_task;
  ELSE reason := 'TASK_DENIED'; END IF;
  INSERT INTO service_desk.read_audit(task_id, correlation_id, operation, reason)
    VALUES(t.id, t.correlation_id,
      CASE WHEN p_action IN ('claim', 'reserve', 'finish', 'stop')
        THEN 'agent_' || p_action ELSE 'agent_denied' END, reason);
  RETURN jsonb_build_object('reason', reason, 'context', to_jsonb(t));
END $$;
REVOKE ALL ON FUNCTION service_desk.agent_action(uuid,text,text,text,integer,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.agent_action(uuid,text,text,text,integer,jsonb)
  TO desk_task_creator;
INSERT INTO service_desk.schema_version(version) VALUES (4);
COMMIT;
