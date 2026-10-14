-- Human-only, exact-record publication. No write tool is added to MCP or the agent.
BEGIN;
CREATE ROLE desk_ticket_publisher NOLOGIN;
GRANT USAGE ON SCHEMA service_desk TO desk_ticket_publisher;

-- Writers take the epoch lock before source rows, matching the publication lock order.
DO $$ DECLARE name text; BEGIN
  FOREACH name IN ARRAY ARRAY['document','document_reader','ticket','ticket_reader',
    'ticket_comment','comment_reader','ticket_reply_participant','principal',
    'identity_binding','read_policy'] LOOP
    EXECUTE format('DROP TRIGGER invalidate_drafts ON service_desk.%I',name);
    EXECUTE format('CREATE TRIGGER invalidate_drafts BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE '
      'ON service_desk.%I FOR EACH STATEMENT EXECUTE FUNCTION service_desk.bump_draft_epoch()',name);
  END LOOP;
END $$;

CREATE TABLE service_desk.draft_confirmation (
  token_hash text PRIMARY KEY CHECK(token_hash ~ '^[0-9a-f]{64}$'),
  draft_id uuid NOT NULL REFERENCES service_desk.requester_draft(id),
  session_hash text NOT NULL CHECK(session_hash ~ '^[0-9a-f]{64}$'),
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL
);
CREATE TABLE service_desk.ticket_publication (
  draft_id uuid PRIMARY KEY REFERENCES service_desk.requester_draft(id),
  token_hash text UNIQUE NOT NULL REFERENCES service_desk.draft_confirmation(token_hash),
  comment_id text UNIQUE NOT NULL REFERENCES service_desk.ticket_comment(id),
  published_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER immutable_confirmation BEFORE UPDATE OR DELETE ON service_desk.draft_confirmation
  FOR EACH ROW EXECUTE FUNCTION service_desk.immutable_draft();
CREATE TRIGGER immutable_publication BEFORE UPDATE OR DELETE ON service_desk.ticket_publication
  FOR EACH ROW EXECUTE FUNCTION service_desk.immutable_draft();
REVOKE ALL ON service_desk.draft_confirmation,service_desk.ticket_publication FROM PUBLIC;

CREATE FUNCTION service_desk.issue_draft_confirmation(
  p_id uuid,p_issuer text,p_subject text,p_session text,p_token text,p_until timestamptz
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE d service_desk.requester_draft; result jsonb; expires timestamptz; reason text := 'ALLOW';
BEGIN
  PERFORM 1 FROM service_desk.draft_epoch FOR UPDATE;
  result := service_desk.review_requester_draft(p_id,p_issuer,p_subject);
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

CREATE FUNCTION service_desk.confirm_requester_reply(
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
      checked := service_desk.review_requester_draft(p_id,p_issuer,p_subject);
      reason := checked->>'reason';
      IF reason='ALLOW' THEN
        IF least(c.expires_at,d.expires_at,p_until)<=clock_timestamp()
          THEN reason := 'TASK_EXPIRED';
        ELSE
          comment := 'reply-' || p_id::text;
          INSERT INTO service_desk.ticket_comment(id,ticket_id,visibility,body)
            VALUES(comment,d.ticket_id,'requester',d.body);
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
    VALUES(t.id,t.correlation_id,'requester_publish',reason);
  -- A slow trigger/audit/lock must roll back all effects, not return a denial after writing.
  IF comment IS NOT NULL AND receipt.draft_id IS NULL
    AND least(c.expires_at,d.expires_at,p_until)<=clock_timestamp()
    THEN RAISE EXCEPTION 'Publication deadline exceeded' USING ERRCODE='57014'; END IF;
  IF reason<>'ALLOW' THEN RETURN jsonb_build_object('reason',reason); END IF;
  RETURN jsonb_build_object('reason','ALLOW','receipt',jsonb_build_object(
    'allowed',true,'status','published','draft_id',p_id,'comment_id',comment,
    'body_sha256',d.body_sha256));
END $$;
REVOKE ALL ON FUNCTION
  service_desk.issue_draft_confirmation(uuid,text,text,text,text,timestamptz),
  service_desk.confirm_requester_reply(uuid,text,text,text,text,text,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  service_desk.issue_draft_confirmation(uuid,text,text,text,text,timestamptz),
  service_desk.confirm_requester_reply(uuid,text,text,text,text,text,timestamptz)
  TO desk_ticket_publisher;
INSERT INTO service_desk.schema_version(version) VALUES(7);
COMMIT;
