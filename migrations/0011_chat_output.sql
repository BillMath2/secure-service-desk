-- Screen self-audience chat output before release, using the same protected-text boundary.
BEGIN;
CREATE FUNCTION service_desk.audience_output_safe(t service_desk.read_task, p_body text, p_sources jsonb)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE viewers text[] := t.recipients || t.principal_id;
  output text; protected text; marker text; width integer; authorized text[];
BEGIN
  IF p_body IS NULL OR octet_length(p_body) NOT BETWEEN 1 AND 8192 THEN RETURN false; END IF;
  output := lower(regexp_replace(p_body,'[[:space:]]+',' ','g'));
  -- Exact overlap with the current authorized source manifest is not a disclosure.
  -- This matters once public guidance is copied into otherwise private ticket comments.
  WITH sources AS MATERIALIZED (
    SELECT value FROM jsonb_array_elements(p_sources)
  ), visible AS (
    SELECT d.body FROM service_desk.document d JOIN sources s
      ON s.value->>'kind'='document' AND s.value->>'id'=d.id
    UNION ALL
    SELECT d.title FROM service_desk.document d JOIN sources s
      ON s.value->>'kind'='document' AND s.value->>'id'=d.id
    UNION ALL
    SELECT x.body FROM service_desk.ticket x JOIN sources s
      ON s.value->>'kind'='ticket' AND s.value->>'id'=x.id
    UNION ALL
    SELECT c.body FROM service_desk.ticket_comment c JOIN sources s
      ON s.value->>'kind'='comment' AND s.value->>'id'=c.id
  ) SELECT array_agg(lower(regexp_replace(body,'[[:space:]]+',' ','g')))
    INTO authorized FROM visible;
  -- These values stay inside the database and never enter prompts, failure logs or previews.
  FOR protected IN
    SELECT d.body FROM service_desk.document d WHERE EXISTS (
      SELECT 1 FROM unnest(viewers) v(id) WHERE NOT EXISTS (
        SELECT 1 FROM service_desk.document_reader r WHERE r.document_id=d.id AND r.principal_id=v.id))
    UNION ALL
    SELECT d.title FROM service_desk.document d WHERE EXISTS (
      SELECT 1 FROM unnest(viewers) v(id) WHERE NOT EXISTS (
        SELECT 1 FROM service_desk.document_reader r WHERE r.document_id=d.id AND r.principal_id=v.id))
    UNION ALL
    SELECT x.body FROM service_desk.ticket x WHERE EXISTS (
      SELECT 1 FROM unnest(viewers) v(id) WHERE NOT EXISTS (
        SELECT 1 FROM service_desk.ticket_reader r WHERE r.ticket_id=x.id AND r.principal_id=v.id))
    UNION ALL
    SELECT c.body FROM service_desk.ticket_comment c JOIN service_desk.ticket x ON x.id=c.ticket_id
      WHERE (c.visibility='internal' AND x.requester=ANY(viewers)) OR EXISTS (
        SELECT 1 FROM unnest(viewers) v(id) WHERE
          NOT EXISTS (SELECT 1 FROM service_desk.ticket_reader r
            WHERE r.ticket_id=c.ticket_id AND r.principal_id=v.id)
          OR NOT EXISTS (SELECT 1 FROM service_desk.comment_reader r
            WHERE r.comment_id=c.id AND r.principal_id=v.id))
  LOOP
    protected := lower(regexp_replace(protected,'[[:space:]]+',' ','g'));
    FOR marker IN SELECT m[1] FROM regexp_matches(protected,'(lab-canary-[a-z0-9-]+)','g') m LOOP
      IF strpos(output,marker)>0 THEN RETURN false; END IF;
    END LOOP;
    -- Exact normalized 32-character fingerprints; shorter protected fields match in full.
    -- This supplements ACLs, and does not claim to detect paraphrases or encodings.
    width := least(32,length(protected));
    IF width >= 8 AND EXISTS (
      SELECT 1 FROM generate_series(1,length(output)-width+1) a(i)
      JOIN generate_series(1,length(protected)-width+1) b(j)
        ON sha256(convert_to(substr(output,a.i,width),'UTF8'))
         = sha256(convert_to(substr(protected,b.j,width),'UTF8'))
      WHERE NOT EXISTS (SELECT 1 FROM unnest(authorized) visible(body)
        WHERE strpos(visible.body,substr(protected,b.j,width))>0)
    ) THEN RETURN false; END IF;
  END LOOP;
  RETURN true;
END $$;

CREATE OR REPLACE FUNCTION service_desk.draft_output_safe(t service_desk.read_task, p_body text)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
  SELECT service_desk.audience_output_safe(t,p_body,service_desk.requester_manifest(t))
$$;
REVOKE ALL ON FUNCTION service_desk.audience_output_safe(service_desk.read_task,text,jsonb) FROM PUBLIC;

CREATE FUNCTION service_desk.finish_chat_answer(
  p_id uuid,p_issuer text,p_subject text,p_body text,p_sources jsonb
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE t service_desk.read_task; reason text;
BEGIN
  PERFORM 1 FROM service_desk.draft_epoch WHERE singleton FOR SHARE;
  SELECT * INTO t FROM service_desk.read_task WHERE id=p_id FOR UPDATE;
  IF NOT FOUND OR t.issuer IS DISTINCT FROM p_issuer OR t.subject IS DISTINCT FROM p_subject
    OR t.draft_audience IS NOT NULL OR t.recipients<>ARRAY[t.principal_id]
    OR NOT t.active OR t.agent_state<>'running'
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  IF NOT service_desk.agent_sources_valid(t,p_sources) THEN reason:='RESOURCE_DENIED';
  ELSIF NOT service_desk.audience_output_safe(t,p_body,p_sources) THEN reason:='OUTPUT_DENIED';
  ELSE RETURN service_desk.agent_action(p_id,p_issuer,p_subject,'finish',0,p_sources);
  END IF;
  UPDATE service_desk.read_task SET active=false,agent_state='stopped' WHERE id=p_id;
  INSERT INTO service_desk.read_audit(task_id,correlation_id,operation,reason)
    VALUES(t.id,t.correlation_id,'agent_finish',reason);
  RETURN jsonb_build_object('reason',reason);
END $$;
REVOKE ALL ON FUNCTION service_desk.finish_chat_answer(uuid,text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.finish_chat_answer(uuid,text,text,text,jsonb) TO desk_task_creator;
INSERT INTO service_desk.schema_version(version) VALUES(11);
COMMIT;
