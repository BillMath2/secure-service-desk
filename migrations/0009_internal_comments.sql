-- Distinct, trusted internal staff audience; shared immutable review/publication machinery.
BEGIN;
ALTER TABLE service_desk.read_task ADD COLUMN draft_audience text
  CHECK(draft_audience IN ('requester','internal'));
UPDATE service_desk.read_task SET draft_audience='requester'
  WHERE id IN (SELECT task_id FROM service_desk.requester_run);
ALTER TABLE service_desk.requester_draft ADD COLUMN audience text NOT NULL DEFAULT 'requester'
  CHECK(audience IN ('requester','internal'));
CREATE TABLE service_desk.ticket_internal_member (
  ticket_id text NOT NULL REFERENCES service_desk.ticket(id),
  principal_id text NOT NULL REFERENCES service_desk.principal(id),
  PRIMARY KEY(ticket_id,principal_id)
);
-- Only the disposable fixture/admin plane seeds this once; subsequent revocations persist.
CREATE TABLE service_desk.internal_fixture_state (singleton boolean PRIMARY KEY CHECK(singleton));
REVOKE ALL ON service_desk.ticket_internal_member, service_desk.internal_fixture_state FROM PUBLIC;
CREATE TRIGGER invalidate_drafts BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE
  ON service_desk.ticket_internal_member FOR EACH STATEMENT
  EXECUTE FUNCTION service_desk.bump_draft_epoch();
CREATE FUNCTION service_desk.internal_recipients(p_ticket text) RETURNS text[]
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
  SELECT array_agg(principal_id ORDER BY principal_id)
  FROM service_desk.ticket_internal_member WHERE ticket_id=p_ticket
$$;
REVOKE ALL ON FUNCTION service_desk.internal_recipients(text) FROM PUBLIC;


CREATE OR REPLACE FUNCTION service_desk.requester_manifest(t service_desk.read_task) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE viewers text[] := t.recipients || t.principal_id; result jsonb;
BEGIN
  IF t.draft_audience IS NULL
    OR (t.draft_audience='requester' AND
      t.recipients IS DISTINCT FROM service_desk.requester_recipients(t.ticket_id))
    OR (t.draft_audience='internal' AND (
      t.recipients IS DISTINCT FROM service_desk.internal_recipients(t.ticket_id)
      OR cardinality(t.recipients)=0
      OR NOT t.principal_id=ANY(t.recipients)
      OR EXISTS (SELECT 1 FROM service_desk.ticket x
        WHERE x.id=t.ticket_id AND x.requester=ANY(viewers))))
    OR NOT EXISTS (SELECT 1 FROM service_desk.identity_binding b
      WHERE b.issuer=t.issuer AND b.subject=t.subject AND b.principal_id=t.principal_id)
    OR EXISTS (SELECT 1 FROM unnest(viewers) AS v(id) WHERE
      NOT EXISTS (SELECT 1 FROM service_desk.principal p WHERE p.id=v.id AND p.kind='human')
      OR NOT EXISTS (SELECT 1 FROM service_desk.ticket_reader r
        WHERE r.ticket_id=t.ticket_id AND r.principal_id=v.id)
      OR NOT EXISTS (SELECT 1 FROM service_desk.document_reader r
        WHERE r.document_id='doc-public' AND r.principal_id=v.id))
    THEN RETURN NULL; END IF;
  -- Fixed recipe: audience-authorized ticket/history and the public support guide.
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
      AND (c.visibility='requester' OR t.draft_audience='internal') AND NOT EXISTS (
        SELECT 1 FROM unnest(viewers) AS v(id) WHERE NOT EXISTS (
          SELECT 1 FROM service_desk.comment_reader r
          WHERE r.comment_id=c.id AND r.principal_id=v.id))
  ) AS items;
  RETURN result;
END $$;

CREATE FUNCTION service_desk.create_ticket_draft_task(
  p_id uuid, p_correlation uuid, p_issuer text, p_subject text, p_ticket text, p_audience text
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE t service_desk.read_task;
BEGIN
  IF p_audience IS NULL OR p_audience NOT IN ('requester','internal') THEN RETURN false; END IF;
  IF p_audience='internal' AND service_desk.internal_recipients(p_ticket) IS NULL
    THEN RETURN false; END IF;
  IF NOT service_desk.create_read_task(p_id,p_correlation,p_issuer,p_subject,p_ticket,'requester')
    THEN RETURN false; END IF;
  UPDATE service_desk.read_task SET draft_audience=p_audience,
    recipients=CASE WHEN p_audience='requester' THEN service_desk.requester_recipients(p_ticket)
      ELSE coalesce(service_desk.internal_recipients(p_ticket),ARRAY[]::text[]) END
    WHERE id=p_id RETURNING * INTO t;
  IF service_desk.requester_manifest(t) IS NULL THEN
    DELETE FROM service_desk.read_task WHERE id=p_id;
    RETURN false;
  END IF;
  INSERT INTO service_desk.requester_run(task_id) VALUES(p_id);
  RETURN true;
END $$;

REVOKE ALL ON FUNCTION service_desk.create_ticket_draft_task(uuid,uuid,text,text,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION service_desk.create_requester_task(
  p_id uuid,p_correlation uuid,p_issuer text,p_subject text,p_ticket text
) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
  SELECT service_desk.create_ticket_draft_task(p_id,p_correlation,p_issuer,p_subject,p_ticket,'requester')
$$;
REVOKE ALL ON FUNCTION service_desk.create_requester_task(uuid,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.create_requester_task(uuid,uuid,text,text,text) TO desk_task_creator;

CREATE OR REPLACE FUNCTION service_desk.create_internal_task(
  p_id uuid,p_correlation uuid,p_issuer text,p_subject text,p_ticket text
) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
  SELECT service_desk.create_ticket_draft_task(p_id,p_correlation,p_issuer,p_subject,p_ticket,'internal')
$$;
REVOKE ALL ON FUNCTION service_desk.create_internal_task(uuid,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.create_internal_task(uuid,uuid,text,text,text) TO desk_task_creator;

CREATE FUNCTION service_desk.ticket_draft_action(
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
      THEN t.draft_audience || '_' || p_action ELSE 'draft_denied' END,reason);
  RETURN jsonb_build_object('reason',reason,'context',to_jsonb(t));
END $$;

REVOKE ALL ON FUNCTION service_desk.ticket_draft_action(uuid,text,text,text,integer,jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION service_desk.requester_action(p_task uuid,p_issuer text,p_subject text,p_action text,p_tokens integer,p_sources jsonb DEFAULT '[]'::jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM service_desk.read_task WHERE id=p_task AND draft_audience='requester')
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  RETURN service_desk.ticket_draft_action(p_task,p_issuer,p_subject,p_action,p_tokens,p_sources);
END $$;
REVOKE ALL ON FUNCTION service_desk.requester_action(uuid,text,text,text,integer,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.requester_action(uuid,text,text,text,integer,jsonb) TO desk_task_creator;

CREATE OR REPLACE FUNCTION service_desk.internal_action(p_task uuid,p_issuer text,p_subject text,p_action text,p_tokens integer,p_sources jsonb DEFAULT '[]'::jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM service_desk.read_task WHERE id=p_task AND draft_audience='internal')
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  RETURN service_desk.ticket_draft_action(p_task,p_issuer,p_subject,p_action,p_tokens,p_sources);
END $$;
REVOKE ALL ON FUNCTION service_desk.internal_action(uuid,text,text,text,integer,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.internal_action(uuid,text,text,text,integer,jsonb) TO desk_task_creator;

CREATE FUNCTION service_desk.save_ticket_draft(
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
    generation := service_desk.ticket_draft_action(p_task,p_issuer,p_subject,'finish',0,p_sources);
    reason := generation->>'reason';
  END IF;
  IF reason='ALLOW' THEN
    INSERT INTO service_desk.requester_draft
      (id,task_id,issuer,subject,ticket_id,recipients,policy_version,epoch,sources,body,
       body_sha256,citations,expires_at,audience)
      VALUES(p_id,p_task,p_issuer,p_subject,t.ticket_id,t.recipients,t.policy_version,current_epoch,
        p_sources,p_body,encode(sha256(convert_to(p_body,'UTF8')),'hex'),p_citations,
        least(p_expires,clock_timestamp()+interval '10 minutes'),t.draft_audience);
  END IF;
  INSERT INTO service_desk.read_audit(task_id,correlation_id,operation,reason)
    VALUES(t.id,t.correlation_id,'draft_save',reason);
  RETURN jsonb_build_object('reason',reason);
END $$;

REVOKE ALL ON FUNCTION service_desk.save_ticket_draft(uuid,uuid,text,text,text,jsonb,jsonb,timestamptz) FROM PUBLIC;

CREATE OR REPLACE FUNCTION service_desk.save_requester_draft(p_id uuid,p_task uuid,p_issuer text,p_subject text,p_body text,p_citations jsonb,p_sources jsonb,p_expires timestamptz)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM service_desk.read_task WHERE id=p_task AND draft_audience='requester')
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  RETURN service_desk.save_ticket_draft(p_id,p_task,p_issuer,p_subject,p_body,p_citations,p_sources,p_expires);
END $$;
REVOKE ALL ON FUNCTION service_desk.save_requester_draft(uuid,uuid,text,text,text,jsonb,jsonb,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.save_requester_draft(uuid,uuid,text,text,text,jsonb,jsonb,timestamptz) TO desk_task_creator;

CREATE OR REPLACE FUNCTION service_desk.save_internal_draft(p_id uuid,p_task uuid,p_issuer text,p_subject text,p_body text,p_citations jsonb,p_sources jsonb,p_expires timestamptz)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM service_desk.read_task WHERE id=p_task AND draft_audience='internal')
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  RETURN service_desk.save_ticket_draft(p_id,p_task,p_issuer,p_subject,p_body,p_citations,p_sources,p_expires);
END $$;
REVOKE ALL ON FUNCTION service_desk.save_internal_draft(uuid,uuid,text,text,text,jsonb,jsonb,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.save_internal_draft(uuid,uuid,text,text,text,jsonb,jsonb,timestamptz) TO desk_task_creator;

CREATE FUNCTION service_desk.review_ticket_draft(p_id uuid,p_issuer text,p_subject text)
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
  ELSIF d.audience IS DISTINCT FROM t.draft_audience OR t.agent_state<>'completed' OR d.recipients IS DISTINCT FROM t.recipients
    OR d.sources IS DISTINCT FROM service_desk.requester_manifest(t)
    THEN reason := 'RESOURCE_DENIED';
  ELSIF NOT service_desk.draft_output_safe(t,d.body) THEN reason := 'OUTPUT_DENIED'; END IF;
  IF d.expires_at<=clock_timestamp() THEN reason := 'TASK_EXPIRED'; END IF;
  INSERT INTO service_desk.read_audit(task_id,correlation_id,operation,reason)
    VALUES(t.id,t.correlation_id,'draft_review',reason);
  IF reason<>'ALLOW' THEN RETURN jsonb_build_object('reason',reason); END IF;
  RETURN jsonb_build_object('reason','ALLOW','draft',jsonb_build_object(
    'allowed',true,'draft_id',d.id,'task_id',d.task_id,'status','unreviewed','audience',d.audience,
    'ticket_id',d.ticket_id,'recipients',d.recipients,'draft',d.body,'body_sha256',d.body_sha256,
    'citations',d.citations,'sources',d.sources,'policy_version',d.policy_version,
    'expires_at',d.expires_at));
END $$;

REVOKE ALL ON FUNCTION service_desk.review_ticket_draft(uuid,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION service_desk.review_requester_draft(p_id uuid,p_issuer text,p_subject text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM service_desk.requester_draft WHERE id=p_id AND audience='requester')
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  RETURN service_desk.review_ticket_draft(p_id,p_issuer,p_subject);
END $$;
REVOKE ALL ON FUNCTION service_desk.review_requester_draft(uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.review_requester_draft(uuid,text,text) TO desk_task_creator;

CREATE OR REPLACE FUNCTION service_desk.review_internal_draft(p_id uuid,p_issuer text,p_subject text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM service_desk.requester_draft WHERE id=p_id AND audience='internal')
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  RETURN service_desk.review_ticket_draft(p_id,p_issuer,p_subject);
END $$;
REVOKE ALL ON FUNCTION service_desk.review_internal_draft(uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.review_internal_draft(uuid,text,text) TO desk_task_creator;

CREATE FUNCTION service_desk.issue_ticket_confirmation(
  p_id uuid,p_issuer text,p_subject text,p_session text,p_token text,p_until timestamptz
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE d service_desk.requester_draft; result jsonb; expires timestamptz; reason text := 'ALLOW';
BEGIN
  PERFORM 1 FROM service_desk.draft_epoch FOR UPDATE;
  result := service_desk.review_ticket_draft(p_id,p_issuer,p_subject);
  IF result->>'reason'<>'ALLOW' THEN RETURN result; END IF;
  SELECT * INTO STRICT d FROM service_desk.requester_draft WHERE id=p_id;
  IF p_session IS NULL OR p_session !~ '^[0-9a-f]{64}$'
    OR p_token IS NULL OR p_token !~ '^[0-9a-f]{64}$' THEN reason := 'TASK_DENIED';
  ELSIF p_until IS NULL OR p_until<=clock_timestamp() THEN reason := 'TASK_EXPIRED';
  ELSIF (SELECT count(*) FROM service_desk.draft_confirmation WHERE draft_id=p_id)>=5
    OR (SELECT count(*) FROM service_desk.draft_confirmation c
      JOIN service_desk.requester_draft x ON x.id=c.draft_id
      WHERE x.issuer=p_issuer AND x.subject=p_subject
        AND c.issued_at>clock_timestamp()-interval '1 minute')>=20
    THEN reason := 'BUDGET_EXHAUSTED';
  END IF;
  IF reason='ALLOW' THEN
    expires := least(d.expires_at,p_until,clock_timestamp()+interval '60 seconds');
    INSERT INTO service_desk.draft_confirmation(token_hash,draft_id,session_hash,expires_at)
      VALUES(p_token,p_id,p_session,expires);
  END IF;
  INSERT INTO service_desk.read_audit(task_id,correlation_id,operation,reason)
    SELECT t.id,t.correlation_id,'confirmation_issue',reason
      FROM service_desk.read_task t WHERE t.id=d.task_id;
  IF reason<>'ALLOW' THEN RETURN jsonb_build_object('reason',reason); END IF;
  RETURN jsonb_build_object('reason','ALLOW','draft',result->'draft','confirmation_expires_at',expires);
END $$;

REVOKE ALL ON FUNCTION service_desk.issue_ticket_confirmation(uuid,text,text,text,text,timestamptz) FROM PUBLIC;

CREATE OR REPLACE FUNCTION service_desk.issue_draft_confirmation(p_id uuid,p_issuer text,p_subject text,p_session text,p_token text,p_until timestamptz)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM service_desk.requester_draft WHERE id=p_id AND audience='requester')
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  RETURN service_desk.issue_ticket_confirmation(p_id,p_issuer,p_subject,p_session,p_token,p_until);
END $$;
REVOKE ALL ON FUNCTION service_desk.issue_draft_confirmation(uuid,text,text,text,text,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.issue_draft_confirmation(uuid,text,text,text,text,timestamptz) TO desk_ticket_publisher;

CREATE OR REPLACE FUNCTION service_desk.issue_internal_confirmation(p_id uuid,p_issuer text,p_subject text,p_session text,p_token text,p_until timestamptz)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM service_desk.requester_draft WHERE id=p_id AND audience='internal')
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  RETURN service_desk.issue_ticket_confirmation(p_id,p_issuer,p_subject,p_session,p_token,p_until);
END $$;
REVOKE ALL ON FUNCTION service_desk.issue_internal_confirmation(uuid,text,text,text,text,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.issue_internal_confirmation(uuid,text,text,text,text,timestamptz) TO desk_ticket_publisher;

CREATE FUNCTION service_desk.confirm_ticket_draft(
  p_id uuid,p_issuer text,p_subject text,p_session text,p_token text,p_body_hash text,
  p_until timestamptz
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE d service_desk.requester_draft; c service_desk.draft_confirmation;
  receipt service_desk.ticket_publication; t service_desk.read_task;
  checked jsonb; reason text := 'ALLOW'; comment text;
BEGIN
  -- All publication and source-policy writers serialize here before accessing ticket rows.
  PERFORM 1 FROM service_desk.draft_epoch FOR UPDATE;
  SELECT * INTO d FROM service_desk.requester_draft WHERE id=p_id;
  IF NOT FOUND OR d.issuer IS DISTINCT FROM p_issuer OR d.subject IS DISTINCT FROM p_subject
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  SELECT * INTO STRICT t FROM service_desk.read_task WHERE id=d.task_id;
  SELECT * INTO c FROM service_desk.draft_confirmation WHERE token_hash=p_token;
  IF NOT FOUND OR c.draft_id IS DISTINCT FROM p_id OR c.session_hash IS DISTINCT FROM p_session
    OR d.body_sha256 IS DISTINCT FROM p_body_hash THEN reason := 'TASK_DENIED';
  ELSIF p_until IS NULL OR p_until<=clock_timestamp() THEN reason := 'TASK_EXPIRED';
  ELSIF NOT EXISTS (SELECT 1 FROM service_desk.identity_binding b
    JOIN service_desk.principal p ON p.id=b.principal_id AND p.kind='human'
    JOIN service_desk.ticket_reader r ON r.principal_id=p.id AND r.ticket_id=d.ticket_id
    WHERE b.issuer=p_issuer AND b.subject=p_subject AND p.id=t.principal_id)
    THEN reason := 'RESOURCE_DENIED';
  ELSE
    SELECT * INTO receipt FROM service_desk.ticket_publication WHERE draft_id=p_id;
    IF FOUND THEN
      -- A lost-response retry acknowledges only the already committed identical confirmation.
      -- It cannot create a new effect, even after the original confirmation expires.
      IF receipt.token_hash<>p_token THEN reason := 'TASK_DENIED';
      ELSE comment := receipt.comment_id; END IF;
    ELSIF c.expires_at<=clock_timestamp() THEN reason := 'TASK_EXPIRED';
    ELSE
      checked := service_desk.review_ticket_draft(p_id,p_issuer,p_subject);
      reason := checked->>'reason';
      IF reason='ALLOW' THEN
        IF least(c.expires_at,d.expires_at,p_until)<=clock_timestamp()
          THEN reason := 'TASK_EXPIRED';
        ELSE
          comment := CASE WHEN d.audience='internal' THEN 'internal-' ELSE 'reply-' END || p_id::text;
          INSERT INTO service_desk.ticket_comment(id,ticket_id,visibility,body)
            VALUES(comment,d.ticket_id,d.audience,d.body);
          -- The author retains access; no additional team audience is inferred.
          INSERT INTO service_desk.comment_reader(comment_id,principal_id)
            SELECT comment,v FROM (SELECT DISTINCT unnest(d.recipients || t.principal_id) v) readers;
          UPDATE service_desk.ticket SET version=version+1 WHERE id=d.ticket_id;
          INSERT INTO service_desk.ticket_publication(draft_id,token_hash,comment_id)
            VALUES(p_id,p_token,comment);
        END IF;
      END IF;
    END IF;
  END IF;
  INSERT INTO service_desk.read_audit(task_id,correlation_id,operation,reason)
    VALUES(t.id,t.correlation_id,d.audience || '_publish',reason);
  -- A slow trigger/audit/lock must roll back all effects, not return a denial after writing.
  IF comment IS NOT NULL AND receipt.draft_id IS NULL
    AND least(c.expires_at,d.expires_at,p_until)<=clock_timestamp()
    THEN RAISE EXCEPTION 'Publication deadline exceeded' USING ERRCODE='57014'; END IF;
  IF reason<>'ALLOW' THEN RETURN jsonb_build_object('reason',reason); END IF;
  RETURN jsonb_build_object('reason','ALLOW','receipt',jsonb_build_object(
    'allowed',true,'status','published','draft_id',p_id,'comment_id',comment,
    'body_sha256',d.body_sha256));
END $$;

REVOKE ALL ON FUNCTION service_desk.confirm_ticket_draft(uuid,text,text,text,text,text,timestamptz) FROM PUBLIC;

CREATE OR REPLACE FUNCTION service_desk.confirm_requester_reply(p_id uuid,p_issuer text,p_subject text,p_session text,p_token text,p_body_hash text,p_until timestamptz)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM service_desk.requester_draft WHERE id=p_id AND audience='requester')
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  RETURN service_desk.confirm_ticket_draft(p_id,p_issuer,p_subject,p_session,p_token,p_body_hash,p_until);
END $$;
REVOKE ALL ON FUNCTION service_desk.confirm_requester_reply(uuid,text,text,text,text,text,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.confirm_requester_reply(uuid,text,text,text,text,text,timestamptz) TO desk_ticket_publisher;

CREATE OR REPLACE FUNCTION service_desk.confirm_internal_comment(p_id uuid,p_issuer text,p_subject text,p_session text,p_token text,p_body_hash text,p_until timestamptz)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM service_desk.requester_draft WHERE id=p_id AND audience='internal')
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  RETURN service_desk.confirm_ticket_draft(p_id,p_issuer,p_subject,p_session,p_token,p_body_hash,p_until);
END $$;
REVOKE ALL ON FUNCTION service_desk.confirm_internal_comment(uuid,text,text,text,text,text,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.confirm_internal_comment(uuid,text,text,text,text,text,timestamptz) TO desk_ticket_publisher;

INSERT INTO service_desk.schema_version(version) VALUES(9);
COMMIT;
