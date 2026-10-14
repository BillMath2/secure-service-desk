-- Screen before persistence; immutable, expiring requester previews. No ticket publication.
BEGIN;
CREATE TABLE service_desk.draft_epoch (
  singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), version bigint NOT NULL
);
INSERT INTO service_desk.draft_epoch VALUES(true,1);
CREATE FUNCTION service_desk.bump_draft_epoch() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
BEGIN
  UPDATE service_desk.draft_epoch SET version=version+1;
  RETURN NULL;
END $$;
-- Coarse invalidation is deliberate: revocation then restoration cannot revive old reviews.
DO $$ DECLARE name text; BEGIN
  FOREACH name IN ARRAY ARRAY['document','document_reader','ticket','ticket_reader',
    'ticket_comment','comment_reader','ticket_reply_participant','principal',
    'identity_binding','read_policy'] LOOP
    EXECUTE format('CREATE TRIGGER invalidate_drafts AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE '
      'ON service_desk.%I FOR EACH STATEMENT EXECUTE FUNCTION service_desk.bump_draft_epoch()',name);
  END LOOP;
END $$;

CREATE TABLE service_desk.requester_draft (
  id uuid PRIMARY KEY, task_id uuid UNIQUE NOT NULL REFERENCES service_desk.read_task(id),
  issuer text NOT NULL, subject text NOT NULL, ticket_id text NOT NULL,
  recipients text[] NOT NULL, policy_version text NOT NULL, epoch bigint NOT NULL,
  sources jsonb NOT NULL, body text NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 8192),
  body_sha256 text NOT NULL CHECK(body_sha256=encode(sha256(convert_to(body,'UTF8')),'hex')),
  citations jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL CHECK(expires_at>created_at)
);
CREATE FUNCTION service_desk.immutable_draft() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,service_desk AS $$
BEGIN RAISE EXCEPTION 'Draft records are immutable'; END $$;
CREATE TRIGGER immutable_draft BEFORE UPDATE OR DELETE ON service_desk.requester_draft
  FOR EACH ROW EXECUTE FUNCTION service_desk.immutable_draft();
REVOKE ALL ON service_desk.requester_draft, service_desk.draft_epoch FROM PUBLIC;

CREATE FUNCTION service_desk.draft_output_safe(t service_desk.read_task, p_body text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE viewers text[] := t.recipients || t.principal_id;
  output text; protected text; marker text; width integer;
BEGIN
  IF p_body IS NULL OR octet_length(p_body) NOT BETWEEN 1 AND 8192 THEN RETURN false; END IF;
  output := lower(regexp_replace(p_body,'[[:space:]]+',' ','g'));
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
    ) THEN RETURN false; END IF;
  END LOOP;
  RETURN true;
END $$;

CREATE FUNCTION service_desk.save_requester_draft(
  p_id uuid,p_task uuid,p_issuer text,p_subject text,p_body text,p_citations jsonb,
  p_sources jsonb,p_expires timestamptz
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE t service_desk.read_task; generation jsonb; current_epoch bigint; reason text := 'ALLOW';
BEGIN
  SELECT * INTO t FROM service_desk.read_task WHERE id=p_task FOR UPDATE;
  IF NOT FOUND OR t.issuer IS DISTINCT FROM p_issuer OR t.subject IS DISTINCT FROM p_subject
    OR NOT EXISTS (SELECT 1 FROM service_desk.requester_run WHERE task_id=p_task)
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  SELECT version INTO current_epoch FROM service_desk.draft_epoch FOR SHARE;
  IF p_expires IS NULL OR p_expires<=clock_timestamp() THEN reason := 'TASK_EXPIRED';
  ELSIF p_citations IS NULL OR jsonb_typeof(p_citations)<>'array'
    OR p_sources IS NULL OR jsonb_typeof(p_sources)<>'array'
    THEN reason := 'RESOURCE_DENIED';
  ELSIF jsonb_array_length(p_citations) NOT BETWEEN 1 AND 16 OR EXISTS (
    SELECT 1 FROM jsonb_array_elements(p_citations) c(value) WHERE jsonb_typeof(c.value)<>'string'
      OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements(p_sources) s(value)
        WHERE s.value->>'kind' IN ('document','ticket') AND
          c.value #>> '{}' = (s.value->>'kind') || ':' || (s.value->>'id') || '@' || (s.value->>'version')))
    THEN reason := 'RESOURCE_DENIED';
  ELSIF NOT service_desk.draft_output_safe(t,p_body) THEN reason := 'OUTPUT_DENIED';
  ELSE
    generation := service_desk.requester_action(p_task,p_issuer,p_subject,'finish',0,p_sources);
    reason := generation->>'reason';
  END IF;
  IF reason='ALLOW' THEN
    INSERT INTO service_desk.requester_draft
      (id,task_id,issuer,subject,ticket_id,recipients,policy_version,epoch,sources,body,
       body_sha256,citations,expires_at)
      VALUES(p_id,p_task,p_issuer,p_subject,t.ticket_id,t.recipients,t.policy_version,current_epoch,
        p_sources,p_body,encode(sha256(convert_to(p_body,'UTF8')),'hex'),p_citations,
        least(p_expires,clock_timestamp()+interval '10 minutes'));
  END IF;
  INSERT INTO service_desk.read_audit(task_id,correlation_id,operation,reason)
    VALUES(t.id,t.correlation_id,'draft_save',reason);
  RETURN jsonb_build_object('reason',reason);
END $$;

CREATE FUNCTION service_desk.review_requester_draft(p_id uuid,p_issuer text,p_subject text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE d service_desk.requester_draft; t service_desk.read_task;
  current_epoch bigint; reason text := 'ALLOW';
BEGIN
  SELECT * INTO d FROM service_desk.requester_draft WHERE id=p_id;
  IF NOT FOUND OR d.issuer IS DISTINCT FROM p_issuer OR d.subject IS DISTINCT FROM p_subject
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  SELECT * INTO STRICT t FROM service_desk.read_task WHERE id=d.task_id;
  SELECT version INTO current_epoch FROM service_desk.draft_epoch FOR SHARE;
  IF d.expires_at<=clock_timestamp() THEN reason := 'TASK_EXPIRED';
  ELSIF d.epoch<>current_epoch OR d.policy_version<>(SELECT version FROM service_desk.read_policy)
    THEN reason := 'POLICY_STALE';
  ELSIF t.agent_state<>'completed' OR d.recipients IS DISTINCT FROM t.recipients
    OR d.sources IS DISTINCT FROM service_desk.requester_manifest(t)
    THEN reason := 'RESOURCE_DENIED';
  ELSIF NOT service_desk.draft_output_safe(t,d.body) THEN reason := 'OUTPUT_DENIED'; END IF;
  IF d.expires_at<=clock_timestamp() THEN reason := 'TASK_EXPIRED'; END IF;
  INSERT INTO service_desk.read_audit(task_id,correlation_id,operation,reason)
    VALUES(t.id,t.correlation_id,'draft_review',reason);
  IF reason<>'ALLOW' THEN RETURN jsonb_build_object('reason',reason); END IF;
  RETURN jsonb_build_object('reason','ALLOW','draft',jsonb_build_object(
    'allowed',true,'draft_id',d.id,'task_id',d.task_id,'status','unreviewed','audience','requester',
    'ticket_id',d.ticket_id,'recipients',d.recipients,'draft',d.body,'body_sha256',d.body_sha256,
    'citations',d.citations,'sources',d.sources,'policy_version',d.policy_version,
    'expires_at',d.expires_at));
END $$;
REVOKE ALL ON FUNCTION service_desk.bump_draft_epoch(),service_desk.immutable_draft(),
  service_desk.draft_output_safe(service_desk.read_task,text),
  service_desk.save_requester_draft(uuid,uuid,text,text,text,jsonb,jsonb,timestamptz),
  service_desk.review_requester_draft(uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  service_desk.save_requester_draft(uuid,uuid,text,text,text,jsonb,jsonb,timestamptz),
  service_desk.review_requester_draft(uuid,text,text) TO desk_task_creator;
INSERT INTO service_desk.schema_version(version) VALUES(6);
COMMIT;
