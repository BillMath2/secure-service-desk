-- Immutable proposals, independent human decisions, executor-only grants and durable audit.
BEGIN;
CREATE ROLE desk_workflow NOLOGIN;
CREATE ROLE desk_collector NOLOGIN;
CREATE ROLE desk_audit_delivery NOLOGIN;
GRANT USAGE ON SCHEMA service_desk TO desk_workflow,desk_access,desk_executor,
  desk_lifecycle,desk_collector,desk_audit_delivery;

CREATE TABLE service_desk.access_lock (singleton boolean PRIMARY KEY CHECK(singleton), version bigint NOT NULL);
INSERT INTO service_desk.access_lock VALUES(true,0);
CREATE TABLE service_desk.access_policy (
  singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), version text NOT NULL,
  standard_seconds integer NOT NULL CHECK(standard_seconds BETWEEN 1 AND 2592000),
  sensitive_seconds integer NOT NULL CHECK(sensitive_seconds BETWEEN 1 AND 28800),
  approval_seconds integer NOT NULL CHECK(approval_seconds BETWEEN 1 AND 900),
  review_seconds integer NOT NULL CHECK(review_seconds BETWEEN 1 AND 604800),
  review_window integer NOT NULL CHECK(review_window BETWEEN 1 AND 86400),
  hourly_requests integer NOT NULL CHECK(hourly_requests BETWEEN 1 AND 5)
);
INSERT INTO service_desk.access_policy VALUES(true,'access-v1',2592000,28800,900,604800,86400,5);
CREATE TABLE service_desk.resource_department (
  resource_id text REFERENCES service_desk.resource_group(id), department text,
  PRIMARY KEY(resource_id,department)
);
CREATE TABLE service_desk.access_analyst (principal_id text PRIMARY KEY REFERENCES service_desk.principal(id));
CREATE TABLE service_desk.audit_reader (principal_id text PRIMARY KEY REFERENCES service_desk.principal(id));
CREATE TABLE service_desk.access_fixture_state (singleton boolean PRIMARY KEY CHECK(singleton));
DO $$ DECLARE n text; BEGIN
  FOREACH n IN ARRAY ARRAY['access_policy','resource_group','resource_department','access_analyst'] LOOP
    EXECUTE format('CREATE TRIGGER invalidate_access BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE '
      'ON service_desk.%I FOR EACH STATEMENT EXECUTE FUNCTION service_desk.bump_draft_epoch()',n);
  END LOOP;
END $$;

CREATE TABLE service_desk.access_request (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), correlation_id uuid NOT NULL,
  triggerer text NOT NULL REFERENCES service_desk.principal(id),
  ticket_id text NOT NULL REFERENCES service_desk.ticket(id),
  submitter text NOT NULL REFERENCES service_desk.principal(id),
  beneficiary text NOT NULL REFERENCES service_desk.principal(id),
  resource_id text NOT NULL REFERENCES service_desk.resource_group(id),
  manager_id text NOT NULL, owner_id text NOT NULL, risk text NOT NULL,
  duration_seconds integer NOT NULL, policy_version text NOT NULL, epoch bigint NOT NULL,
  provenance jsonb NOT NULL, action jsonb NOT NULL, action_hash text NOT NULL,
  justification text NOT NULL CHECK(octet_length(justification) BETWEEN 1 AND 2048),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(action_hash=encode(sha256(convert_to(action::text,'UTF8')),'hex'))
);
CREATE TRIGGER access_request_immutable BEFORE UPDATE OR DELETE ON service_desk.access_request
  FOR EACH ROW EXECUTE FUNCTION service_desk.immutable_draft();
CREATE TABLE service_desk.access_state (
  request_id uuid PRIMARY KEY REFERENCES service_desk.access_request(id),
  state text NOT NULL CHECK(state IN ('draft','pending','approved','consumed','rejected')),
  submitted_at timestamptz, expires_at timestamptz NOT NULL
);
CREATE TABLE service_desk.access_confirmation (
  token_hash text PRIMARY KEY CHECK(token_hash ~ '^[a-f0-9]{64}$'),
  request_id uuid NOT NULL REFERENCES service_desk.access_request(id),
  actor text NOT NULL, session_hash text NOT NULL CHECK(session_hash ~ '^[a-f0-9]{64}$'),
  operation text NOT NULL CHECK(operation IN ('submit','approve','review')),
  stage integer NOT NULL, action_hash text NOT NULL, expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE service_desk.access_confirmation_use (
  token_hash text PRIMARY KEY REFERENCES service_desk.access_confirmation(token_hash)
);
CREATE TABLE service_desk.access_approval (
  request_id uuid REFERENCES service_desk.access_request(id), stage integer CHECK(stage IN (1,2)),
  approver text NOT NULL, action_hash text NOT NULL, decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(request_id,stage), UNIQUE(request_id,approver)
);
CREATE TABLE service_desk.access_grant (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), request_id uuid UNIQUE NOT NULL REFERENCES service_desk.access_request(id),
  beneficiary text NOT NULL, resource_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL, review_due timestamptz NOT NULL, review_deadline timestamptz NOT NULL,
  revoked_at timestamptz, revoke_reason text,
  CHECK(expires_at>created_at), CHECK(review_deadline>=review_due)
);
CREATE TABLE service_desk.directory_membership (
  grant_id uuid PRIMARY KEY REFERENCES service_desk.access_grant(id), beneficiary text NOT NULL, resource_id text NOT NULL
);
CREATE TABLE service_desk.audit_outbox (
  sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, event_id uuid UNIQUE NOT NULL DEFAULT gen_random_uuid(),
  writer text NOT NULL CHECK(writer IN ('workflow','execution','lifecycle','reads')),
  payload jsonb NOT NULL, delivered_at timestamptz
);
CREATE TABLE service_desk.collected_audit (
  writer text NOT NULL, event_id uuid NOT NULL, payload jsonb NOT NULL,
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(writer,event_id)
);
DO $$ DECLARE n text; BEGIN
  FOREACH n IN ARRAY ARRAY['access_confirmation','access_confirmation_use','access_approval','collected_audit'] LOOP
    EXECUTE format('CREATE TRIGGER immutable_record BEFORE UPDATE OR DELETE ON service_desk.%I '
      'FOR EACH ROW EXECUTE FUNCTION service_desk.immutable_draft()',n);
  END LOOP;
END $$;

CREATE FUNCTION service_desk.access_actor(i text,s text) RETURNS text LANGUAGE sql STABLE
SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
 SELECT b.principal_id FROM service_desk.identity_binding b JOIN service_desk.principal p ON p.id=b.principal_id
 WHERE b.issuer=i AND b.subject=s AND p.kind='human'
$$;
CREATE FUNCTION service_desk.access_event(w text,c uuid,a text,o text,op text,r text,st integer DEFAULT 0)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
 INSERT INTO service_desk.audit_outbox(writer,payload) VALUES(w,jsonb_build_object(
  'writer',w,'correlation_id',c,'actor',a,'object_id',o,'operation',op,'reason',r,'stage',st,
  'policy_version',(SELECT version FROM service_desk.access_policy),'occurred_at',clock_timestamp()))
$$;
CREATE FUNCTION service_desk.read_audit_outbox() RETURNS trigger LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
BEGIN
 PERFORM service_desk.access_event('reads',NEW.correlation_id,
  (SELECT principal_id FROM service_desk.read_task WHERE id=NEW.task_id),NEW.task_id::text,NEW.operation,NEW.reason);
 RETURN NEW;
END $$;
CREATE TRIGGER export_read_audit AFTER INSERT ON service_desk.read_audit
 FOR EACH ROW EXECUTE FUNCTION service_desk.read_audit_outbox();

CREATE FUNCTION service_desk.access_sources(t text) RETURNS jsonb LANGUAGE sql STABLE
SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
 SELECT jsonb_build_array(jsonb_build_object('kind','ticket','id',id,'version',version,
 'body_sha256',encode(sha256(convert_to(body,'UTF8')),'hex'),'submitted_at',submitted_at,'submitter',requester))
 FROM service_desk.ticket WHERE id=t
$$;
CREATE FUNCTION service_desk.access_valid(r service_desk.access_request) RETURNS boolean LANGUAGE sql STABLE
SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
 SELECT r.epoch=(SELECT version FROM service_desk.draft_epoch)
 AND r.policy_version=(SELECT version FROM service_desk.access_policy)
 AND r.provenance=service_desk.access_sources(r.ticket_id)
 AND EXISTS(SELECT 1 FROM service_desk.access_analyst WHERE principal_id=r.triggerer)
 AND EXISTS(SELECT 1 FROM service_desk.principal p JOIN service_desk.resource_department d ON d.department=p.department
  WHERE p.id=r.beneficiary AND p.kind='human' AND p.manager_id=r.manager_id AND d.resource_id=r.resource_id)
 AND EXISTS(SELECT 1 FROM service_desk.resource_group g WHERE g.id=r.resource_id AND g.owner_id=r.owner_id AND g.risk=r.risk)
 AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY[r.triggerer,r.submitter,r.beneficiary,r.manager_id,r.owner_id]) v(id)
  WHERE NOT EXISTS(SELECT 1 FROM service_desk.ticket_reader tr WHERE tr.ticket_id=r.ticket_id AND tr.principal_id=v.id))
 AND r.manager_id<>ALL(ARRAY[r.triggerer,r.submitter,r.beneficiary])
 AND r.owner_id<>ALL(ARRAY[r.triggerer,r.submitter,r.beneficiary]) AND r.manager_id<>r.owner_id
 AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY[r.manager_id,r.owner_id]) v(id)
  WHERE NOT EXISTS(SELECT 1 FROM service_desk.principal p WHERE p.id=v.id AND p.kind='human'))
$$;

CREATE FUNCTION service_desk.access_draft(i text,s text,t text,g text,seconds integer,why text,task uuid DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE a text:=service_desk.access_actor(i,s); r service_desk.access_request; p service_desk.access_policy;
 x service_desk.ticket; target service_desk.principal; resource service_desk.resource_group;
 ctx service_desk.read_task; corr uuid:=gen_random_uuid(); readers text[];
BEGIN
 PERFORM 1 FROM service_desk.draft_epoch WHERE singleton FOR SHARE;
 UPDATE service_desk.access_lock SET version=version+1 WHERE singleton;
 SELECT * INTO p FROM service_desk.access_policy;
 SELECT * INTO x FROM service_desk.ticket WHERE id=t;
 SELECT * INTO target FROM service_desk.principal WHERE id=x.requester AND kind='human';
 SELECT * INTO resource FROM service_desk.resource_group WHERE id=g;
 IF task IS NOT NULL THEN
  SELECT * INTO ctx FROM service_desk.read_task WHERE id=task FOR UPDATE;
  IF ctx.id IS NULL OR ctx.principal_id IS DISTINCT FROM a OR ctx.ticket_id IS DISTINCT FROM t
    OR NOT ctx.active OR ctx.deadline<=clock_timestamp() OR ctx.recipients<>ARRAY[a]
    OR ctx.used_calls>ctx.max_calls OR ctx.policy_version<>(SELECT version FROM service_desk.read_policy)
    THEN RETURN jsonb_build_object('reason','TASK_DENIED'); END IF;
  corr:=ctx.correlation_id;
 END IF;
 IF a IS NULL OR x.id IS NULL OR target.id IS NULL OR resource.id IS NULL
  OR NOT EXISTS(SELECT 1 FROM service_desk.access_analyst WHERE principal_id=a)
  OR NOT EXISTS(SELECT 1 FROM service_desk.ticket_reader WHERE ticket_id=t AND principal_id=a)
  OR target.manager_id IS NULL OR resource.owner_id IS NULL
  OR seconds IS NOT NULL AND (seconds<1 OR seconds>CASE WHEN resource.risk='sensitive' THEN p.sensitive_seconds ELSE p.standard_seconds END)
  OR why IS NULL OR octet_length(why) NOT BETWEEN 1 AND 2048 THEN
  PERFORM service_desk.access_event('workflow',corr,a,NULL,'draft','POLICY_DENIED');
  RETURN jsonb_build_object('reason','POLICY_DENIED');
 END IF;
 IF (SELECT count(*) FROM service_desk.access_request WHERE triggerer=a AND created_at>clock_timestamp()-interval '1 hour')>=20 THEN
  RETURN jsonb_build_object('reason','BUDGET_EXHAUSTED'); END IF;
 r.id:=gen_random_uuid(); r.correlation_id:=corr; r.triggerer:=a; r.ticket_id:=t; r.submitter:=x.requester;
 r.beneficiary:=target.id; r.resource_id:=g; r.manager_id:=target.manager_id; r.owner_id:=resource.owner_id; r.risk:=resource.risk;
 r.duration_seconds:=coalesce(seconds,CASE WHEN resource.risk='sensitive' THEN p.sensitive_seconds ELSE p.standard_seconds END);
 r.policy_version:=p.version; SELECT version INTO r.epoch FROM service_desk.draft_epoch;
 r.provenance:=service_desk.access_sources(t); r.justification:=why; r.created_at:=clock_timestamp();
 IF NOT coalesce(service_desk.access_valid(r),false) THEN
  PERFORM service_desk.access_event('workflow',corr,a,NULL,'draft','POLICY_DENIED');
  RETURN jsonb_build_object('reason','POLICY_DENIED'); END IF;
 readers:=ARRAY[a,r.submitter,r.manager_id,r.owner_id]; ctx.principal_id:=a; ctx.recipients:=readers;
 IF NOT service_desk.audience_output_safe(ctx,why,r.provenance) THEN
  PERFORM service_desk.access_event('workflow',corr,a,NULL,'draft','OUTPUT_DENIED');
  RETURN jsonb_build_object('reason','OUTPUT_DENIED'); END IF;
 r.action:=jsonb_build_object('request_id',r.id,'ticket_id',t,'submitter',r.submitter,'triggerer',a,
  'beneficiary',r.beneficiary,'resource_id',g,'change','grant','duration_seconds',r.duration_seconds,
  'manager',r.manager_id,'owner',r.owner_id,'risk',r.risk,'sources',r.provenance,'policy_version',r.policy_version,
  'justification_sha256',encode(sha256(convert_to(why,'UTF8')),'hex'));
 r.action_hash:=encode(sha256(convert_to(r.action::text,'UTF8')),'hex');
 PERFORM service_desk.access_event('workflow',corr,a,r.id::text,'draft','INTENT');
 INSERT INTO service_desk.access_request SELECT r.*;
 INSERT INTO service_desk.access_state VALUES(r.id,'draft',NULL,clock_timestamp()+interval '10 minutes');
 PERFORM service_desk.access_event('workflow',corr,a,r.id::text,'draft','ALLOW');
 IF task IS NOT NULL AND clock_timestamp()>=ctx.deadline THEN RAISE EXCEPTION 'Task deadline exceeded'; END IF;
 RETURN jsonb_build_object('reason','ALLOW','request_id',r.id,'action_hash',r.action_hash,'correlation_id',corr);
END $$;

CREATE FUNCTION service_desk.access_view(i text,s text,id uuid) RETURNS jsonb LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE a text:=service_desk.access_actor(i,s); r service_desk.access_request; state service_desk.access_state;
BEGIN
 PERFORM 1 FROM service_desk.draft_epoch WHERE singleton FOR SHARE;
 SELECT * INTO r FROM service_desk.access_request WHERE access_request.id=access_view.id;
 SELECT * INTO state FROM service_desk.access_state WHERE request_id=access_view.id;
 IF r.id IS NULL OR a IS NULL OR a<>ALL(ARRAY[r.triggerer,r.submitter,r.manager_id,r.owner_id])
  OR NOT EXISTS(SELECT 1 FROM service_desk.ticket_reader WHERE ticket_id=r.ticket_id AND principal_id=a)
  OR r.provenance IS DISTINCT FROM service_desk.access_sources(r.ticket_id)
  OR NOT coalesce(service_desk.access_valid(r),false) THEN
  RETURN jsonb_build_object('reason','RESOURCE_DENIED'); END IF;
 RETURN jsonb_build_object('reason','ALLOW','request_id',r.id,'correlation_id',r.correlation_id,
  'ticket',jsonb_build_object('id',r.ticket_id,'submitter',r.submitter,
    'submitted_at',(SELECT submitted_at FROM service_desk.ticket WHERE ticket.id=r.ticket_id),
    'body',(SELECT body FROM service_desk.ticket WHERE ticket.id=r.ticket_id)),
  'sources',r.provenance,'policy_valid',coalesce(service_desk.access_valid(r),false),
  'policy_version',r.policy_version,'state',state.state,'expires_at',state.expires_at,
  'approvals',coalesce((SELECT jsonb_agg(to_jsonb(v) ORDER BY v.stage) FROM service_desk.access_approval v WHERE v.request_id=access_view.id),'[]'::jsonb),
  'action',r.action,'action_hash',r.action_hash,'justification',r.justification,
  'grant',(SELECT to_jsonb(v) FROM service_desk.access_grant v WHERE v.request_id=access_view.id));
END $$;

CREATE FUNCTION service_desk.access_eligible(r service_desk.access_request,a text,stage integer) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
 SELECT a IS NOT NULL AND a<>ALL(ARRAY[r.triggerer,r.submitter,r.beneficiary])
 AND CASE WHEN r.risk='standard' THEN stage=1 AND a=ANY(ARRAY[r.manager_id,r.owner_id])
 WHEN stage=1 THEN a=r.manager_id WHEN stage=2 THEN a=r.owner_id ELSE false END
$$;
CREATE FUNCTION service_desk.access_review(i text,s text,id uuid,session text,token text,op text,expires timestamptz)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE a text:=service_desk.access_actor(i,s); r service_desk.access_request; state service_desk.access_state;
 n integer; view jsonb; grant_row service_desk.access_grant;
BEGIN
 PERFORM 1 FROM service_desk.draft_epoch WHERE singleton FOR SHARE; UPDATE service_desk.access_lock SET version=version+1 WHERE singleton;
 SELECT * INTO r FROM service_desk.access_request WHERE access_request.id=access_review.id;
 SELECT * INTO state FROM service_desk.access_state WHERE request_id=access_review.id FOR UPDATE;
 view:=service_desk.access_view(i,s,id);
 SELECT count(*)+1 INTO n FROM service_desk.access_approval WHERE request_id=access_review.id;
 SELECT * INTO grant_row FROM service_desk.access_grant WHERE request_id=access_review.id;
 IF view->>'reason'<>'ALLOW' OR NOT coalesce(service_desk.access_valid(r),false)
  OR expires IS NULL OR expires<=clock_timestamp() OR token !~ '^[a-f0-9]{64}$' OR session !~ '^[a-f0-9]{64}$'
  OR NOT coalesce(CASE op
    WHEN 'submit' THEN a=r.triggerer AND state.state='draft' AND state.expires_at>clock_timestamp()
    WHEN 'approve' THEN state.state='pending' AND state.expires_at>clock_timestamp() AND service_desk.access_eligible(r,a,n)
    WHEN 'review' THEN state.state='consumed' AND r.risk='standard' AND service_desk.access_eligible(r,a,1)
      AND grant_row.revoked_at IS NULL AND grant_row.expires_at>clock_timestamp() AND grant_row.review_deadline>clock_timestamp()
    ELSE false END,false) THEN RETURN jsonb_build_object('reason','APPROVAL_DENIED'); END IF;
 IF (SELECT count(*) FROM service_desk.access_confirmation WHERE actor=a AND created_at>clock_timestamp()-interval '1 minute')>=20
  THEN RETURN jsonb_build_object('reason','BUDGET_EXHAUSTED'); END IF;
 expires:=least(expires,clock_timestamp()+interval '5 minutes',CASE WHEN op='review' THEN grant_row.review_deadline ELSE state.expires_at END);
 INSERT INTO service_desk.access_confirmation VALUES(token,id,a,session,op,n,r.action_hash,expires,clock_timestamp());
 RETURN view||jsonb_build_object('operation',op,'stage',n,'confirmation_expires_at',expires);
END $$;

CREATE FUNCTION service_desk.access_confirm(i text,s text,id uuid,session text,token text,hash text,deadline timestamptz)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE a text:=service_desk.access_actor(i,s); r service_desk.access_request; state service_desk.access_state;
 c service_desk.access_confirmation; p service_desk.access_policy; n integer; g service_desk.access_grant; reason text:='APPROVAL_DENIED';
BEGIN
 PERFORM 1 FROM service_desk.draft_epoch WHERE singleton FOR SHARE; UPDATE service_desk.access_lock SET version=version+1 WHERE singleton;
 SELECT * INTO r FROM service_desk.access_request WHERE access_request.id=access_confirm.id;
 SELECT * INTO state FROM service_desk.access_state WHERE request_id=access_confirm.id FOR UPDATE;
 SELECT * INTO c FROM service_desk.access_confirmation WHERE token_hash=token;
 SELECT * INTO p FROM service_desk.access_policy;
 SELECT count(*)+1 INTO n FROM service_desk.access_approval WHERE request_id=access_confirm.id;
 SELECT * INTO g FROM service_desk.access_grant WHERE request_id=access_confirm.id FOR UPDATE;
 IF r.id IS NOT NULL AND a IS NOT NULL AND c.actor=a AND c.request_id=access_confirm.id AND c.session_hash=session
  AND c.action_hash=hash AND hash=r.action_hash AND c.expires_at>clock_timestamp()
  AND deadline>clock_timestamp() AND deadline<=statement_timestamp()+interval '6 seconds'
  AND NOT EXISTS(SELECT 1 FROM service_desk.access_confirmation_use WHERE token_hash=token)
  AND coalesce(service_desk.access_valid(r),false) THEN
  IF c.operation='submit' AND state.state='draft' AND a=r.triggerer AND state.expires_at>clock_timestamp() THEN
   IF (SELECT count(*) FROM service_desk.access_state st JOIN service_desk.access_request ar ON ar.id=st.request_id
    WHERE ar.triggerer=a AND st.submitted_at>clock_timestamp()-interval '1 hour')>=p.hourly_requests
    OR (SELECT count(*) FROM service_desk.access_state WHERE access_state.state IN ('pending','approved') AND expires_at>clock_timestamp())>=64 THEN
    reason:='BUDGET_EXHAUSTED';
   ELSE
    PERFORM service_desk.access_event('workflow',r.correlation_id,a,id::text,'submit','INTENT');
    UPDATE service_desk.access_state SET state='pending',submitted_at=clock_timestamp(),
      expires_at=clock_timestamp()+make_interval(secs=>p.approval_seconds) WHERE request_id=access_confirm.id;
    reason:='ALLOW';
   END IF;
  ELSIF c.operation='approve' AND state.state='pending' AND state.expires_at>clock_timestamp()
   AND c.stage=n AND service_desk.access_eligible(r,a,n) THEN
   PERFORM service_desk.access_event('workflow',r.correlation_id,a,id::text,'approve','INTENT',n);
   INSERT INTO service_desk.access_approval VALUES(id,n,a,hash,clock_timestamp());
   IF r.risk='standard' OR n=2 THEN UPDATE service_desk.access_state SET state='approved' WHERE request_id=access_confirm.id; END IF;
   reason:='ALLOW';
  ELSIF c.operation='review' AND state.state='consumed' AND r.risk='standard' AND service_desk.access_eligible(r,a,1)
   AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp() AND g.review_deadline>clock_timestamp() THEN
   PERFORM service_desk.access_event('workflow',r.correlation_id,a,id::text,'review','INTENT');
   UPDATE service_desk.access_grant SET review_due=clock_timestamp()+make_interval(secs=>p.review_seconds),
    review_deadline=clock_timestamp()+make_interval(secs=>p.review_seconds+p.review_window) WHERE request_id=access_confirm.id;
   reason:='ALLOW';
  END IF;
 END IF;
 IF reason='ALLOW' THEN INSERT INTO service_desk.access_confirmation_use VALUES(token); END IF;
 PERFORM service_desk.access_event('workflow',coalesce(r.correlation_id,gen_random_uuid()),a,
  CASE WHEN r.id IS NOT NULL THEN id::text END,coalesce(c.operation,'confirm'),reason,coalesce(c.stage,0));
 IF clock_timestamp()>=deadline THEN RAISE EXCEPTION 'Operation deadline exceeded'; END IF;
 RETURN jsonb_build_object('reason',reason,'request_id',id,'state',(SELECT access_state.state FROM service_desk.access_state WHERE request_id=access_confirm.id));
END $$;

CREATE FUNCTION service_desk.access_execute(id uuid,hash text,deadline timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE r service_desk.access_request; state service_desk.access_state; g service_desk.access_grant;
 p service_desk.access_policy; n integer;
BEGIN
 PERFORM 1 FROM service_desk.draft_epoch WHERE singleton FOR SHARE; UPDATE service_desk.access_lock SET version=version+1 WHERE singleton;
 SELECT * INTO r FROM service_desk.access_request WHERE access_request.id=access_execute.id;
 SELECT * INTO state FROM service_desk.access_state WHERE request_id=access_execute.id FOR UPDATE;
 SELECT * INTO g FROM service_desk.access_grant WHERE request_id=access_execute.id;
 SELECT * INTO p FROM service_desk.access_policy;
 IF r.id IS NULL OR hash IS DISTINCT FROM r.action_hash OR deadline IS NULL OR deadline<=clock_timestamp()
   OR deadline>statement_timestamp()+interval '6 seconds' THEN RETURN jsonb_build_object('reason','EXECUTION_DENIED'); END IF;
 IF state.state='consumed' AND g.id IS NOT NULL THEN
  RETURN jsonb_build_object('reason','ALLOW','grant_id',g.id,'request_id',id,'expires_at',g.expires_at); END IF;
 SELECT count(*) INTO n FROM service_desk.access_approval WHERE request_id=access_execute.id;
 IF state.state<>'approved' OR state.expires_at<=clock_timestamp() OR NOT coalesce(service_desk.access_valid(r),false)
  OR n<>(CASE WHEN r.risk='sensitive' THEN 2 ELSE 1 END)
  OR EXISTS(SELECT 1 FROM service_desk.access_approval a WHERE a.request_id=access_execute.id
    AND (a.action_hash<>hash OR NOT service_desk.access_eligible(r,a.approver,a.stage))) THEN
  PERFORM service_desk.access_event('execution',r.correlation_id,'executor',id::text,'execute','EXECUTION_DENIED');
  RETURN jsonb_build_object('reason','EXECUTION_DENIED'); END IF;
 PERFORM service_desk.access_event('execution',r.correlation_id,'executor',id::text,'execute','INTENT');
 INSERT INTO service_desk.access_grant(request_id,beneficiary,resource_id,expires_at,review_due,review_deadline)
 VALUES(id,r.beneficiary,r.resource_id,clock_timestamp()+make_interval(secs=>r.duration_seconds),
  clock_timestamp()+make_interval(secs=>p.review_seconds),clock_timestamp()+make_interval(secs=>p.review_seconds+p.review_window)) RETURNING * INTO g;
 INSERT INTO service_desk.directory_membership VALUES(g.id,g.beneficiary,g.resource_id);
 UPDATE service_desk.access_state SET state='consumed' WHERE request_id=access_execute.id;
 PERFORM service_desk.access_event('execution',r.correlation_id,'executor',id::text,'execute','ALLOW');
 IF clock_timestamp()>=deadline THEN RAISE EXCEPTION 'Operation deadline exceeded'; END IF;
 RETURN jsonb_build_object('reason','ALLOW','grant_id',g.id,'request_id',id,'expires_at',g.expires_at);
END $$;

CREATE FUNCTION service_desk.access_queue() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
 SELECT coalesce(jsonb_agg(x),'[]'::jsonb) FROM (SELECT r.id AS request_id,r.action_hash FROM service_desk.access_request r
 JOIN service_desk.access_state s ON s.request_id=r.id WHERE s.state='approved' AND s.expires_at>clock_timestamp()
 AND service_desk.access_valid(r) ORDER BY r.created_at LIMIT 16) x
$$;
CREATE FUNCTION service_desk.access_effective(b text,g text) RETURNS boolean LANGUAGE sql
SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
 SELECT EXISTS(SELECT 1 FROM service_desk.access_grant WHERE beneficiary=b AND resource_id=g
  AND revoked_at IS NULL AND expires_at>clock_timestamp() AND review_deadline>clock_timestamp())
$$;
CREATE FUNCTION service_desk.access_check(i text,s text,b text,g text) RETURNS jsonb LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE a text:=service_desk.access_actor(i,s);
BEGIN
 IF a IS NULL OR NOT (a=b OR EXISTS(SELECT 1 FROM service_desk.access_analyst an
  JOIN service_desk.ticket_reader tr ON tr.principal_id=an.principal_id JOIN service_desk.ticket t ON t.id=tr.ticket_id
  WHERE an.principal_id=a AND t.requester=b)) THEN RETURN jsonb_build_object('reason','RESOURCE_DENIED'); END IF;
 RETURN jsonb_build_object('reason','ALLOW','effective',service_desk.access_effective(b,g));
END $$;

CREATE FUNCTION service_desk.access_reconcile(deadline timestamptz) RETURNS jsonb LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE g service_desk.access_grant; r service_desk.access_request; changed integer:=0;
BEGIN
 UPDATE service_desk.access_lock SET version=version+1 WHERE singleton;
 IF deadline IS NULL OR deadline<=clock_timestamp() OR deadline>statement_timestamp()+interval '6 seconds' THEN
  RETURN jsonb_build_object('reason','TASK_EXPIRED'); END IF;
 FOR g IN SELECT * FROM service_desk.access_grant WHERE revoked_at IS NULL
  AND (expires_at<=clock_timestamp() OR review_deadline<=clock_timestamp()) ORDER BY created_at LIMIT 64 FOR UPDATE LOOP
  SELECT * INTO r FROM service_desk.access_request WHERE id=g.request_id;
  PERFORM service_desk.access_event('lifecycle',r.correlation_id,'lifecycle-worker',r.id::text,'revoke','INTENT');
  UPDATE service_desk.access_grant SET revoked_at=clock_timestamp(),
   revoke_reason=CASE WHEN expires_at<=clock_timestamp() THEN 'EXPIRED' ELSE 'REVIEW_MISSED' END WHERE id=g.id;
  DELETE FROM service_desk.directory_membership WHERE grant_id=g.id;
  PERFORM service_desk.access_event('lifecycle',r.correlation_id,'lifecycle-worker',r.id::text,'revoke','ALLOW');
  changed:=changed+1;
 END LOOP;
 FOR g IN SELECT * FROM service_desk.access_grant gr WHERE revoked_at IS NULL AND expires_at>clock_timestamp()
  AND review_deadline>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM service_desk.directory_membership m WHERE m.grant_id=gr.id)
  ORDER BY created_at LIMIT 64 LOOP
  SELECT * INTO r FROM service_desk.access_request WHERE id=g.request_id;
  PERFORM service_desk.access_event('lifecycle',r.correlation_id,'lifecycle-worker',r.id::text,'reconcile','INTENT');
  INSERT INTO service_desk.directory_membership VALUES(g.id,g.beneficiary,g.resource_id);
  PERFORM service_desk.access_event('lifecycle',r.correlation_id,'lifecycle-worker',r.id::text,'reconcile','ALLOW');
  changed:=changed+1;
 END LOOP;
 IF clock_timestamp()>=deadline THEN RAISE EXCEPTION 'Operation deadline exceeded'; END IF;
 RETURN jsonb_build_object('reason','ALLOW','changed',changed);
END $$;

CREATE FUNCTION service_desk.audit_writer_name() RETURNS text LANGUAGE sql STABLE
SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
 SELECT CASE session_user WHEN 'access_workflow' THEN 'workflow' WHEN 'access_executor' THEN 'execution'
  WHEN 'access_lifecycle' THEN 'lifecycle' WHEN 'access_delivery' THEN 'reads' END
$$;
CREATE FUNCTION service_desk.audit_batch() RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
 SELECT coalesce(jsonb_agg(x),'[]'::jsonb) FROM (SELECT event_id,payload FROM service_desk.audit_outbox
 WHERE writer=service_desk.audit_writer_name() AND delivered_at IS NULL ORDER BY sequence LIMIT 64) x
$$;
CREATE FUNCTION service_desk.audit_ack(id uuid) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
 UPDATE service_desk.audit_outbox SET delivered_at=clock_timestamp()
 WHERE event_id=id AND writer=service_desk.audit_writer_name() AND delivered_at IS NULL
$$;
CREATE FUNCTION service_desk.audit_accept(w text,id uuid,data jsonb) RETURNS boolean LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE old jsonb;
BEGIN
 IF w<>ALL(ARRAY['workflow','execution','lifecycle','reads']) OR data->>'writer' IS DISTINCT FROM w
  OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(data) k) IS DISTINCT FROM
   ARRAY['actor','correlation_id','object_id','occurred_at','operation','policy_version','reason','stage','writer']
  OR octet_length(data::text)>4096 THEN RETURN false; END IF;
 INSERT INTO service_desk.collected_audit VALUES(w,id,data,clock_timestamp()) ON CONFLICT DO NOTHING;
 SELECT payload INTO old FROM service_desk.collected_audit WHERE writer=w AND event_id=id;
 RETURN old=data;
END $$;
CREATE FUNCTION service_desk.audit_query(i text,s text,c uuid) RETURNS jsonb LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM service_desk.audit_reader WHERE principal_id=service_desk.access_actor(i,s)) THEN
  RETURN jsonb_build_object('reason','RESOURCE_DENIED'); END IF;
 RETURN jsonb_build_object('reason','ALLOW','events',coalesce((SELECT jsonb_agg(x) FROM
  (SELECT event_id,payload FROM service_desk.collected_audit WHERE payload->>'correlation_id'=c::text
   ORDER BY received_at,event_id LIMIT 200) x),'[]'::jsonb));
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA service_desk FROM PUBLIC;
REVOKE ALL ON FUNCTION service_desk.access_actor(text,text),service_desk.access_event(text,uuid,text,text,text,text,integer),
 service_desk.read_audit_outbox(),service_desk.access_sources(text),service_desk.access_valid(service_desk.access_request),
 service_desk.access_eligible(service_desk.access_request,text,integer),service_desk.access_effective(text,text),
 service_desk.audit_writer_name() FROM PUBLIC;
REVOKE ALL ON FUNCTION service_desk.access_draft(text,text,text,text,integer,text,uuid),
 service_desk.access_view(text,text,uuid),service_desk.access_review(text,text,uuid,text,text,text,timestamptz),
 service_desk.access_confirm(text,text,uuid,text,text,text,timestamptz),service_desk.access_execute(uuid,text,timestamptz),
 service_desk.access_queue(),service_desk.access_check(text,text,text,text),service_desk.access_reconcile(timestamptz),
 service_desk.audit_batch(),service_desk.audit_ack(uuid),service_desk.audit_accept(text,uuid,jsonb),service_desk.audit_query(text,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION service_desk.access_draft(text,text,text,text,integer,text,uuid),service_desk.access_view(text,text,uuid),
 service_desk.access_review(text,text,uuid,text,text,text,timestamptz),service_desk.access_confirm(text,text,uuid,text,text,text,timestamptz),
 service_desk.access_check(text,text,text,text),service_desk.audit_query(text,text,uuid) TO desk_workflow;
GRANT EXECUTE ON FUNCTION service_desk.access_execute(uuid,text,timestamptz),service_desk.access_queue() TO desk_executor;
GRANT EXECUTE ON FUNCTION service_desk.access_reconcile(timestamptz) TO desk_lifecycle;
GRANT EXECUTE ON FUNCTION service_desk.audit_batch(),service_desk.audit_ack(uuid) TO desk_workflow,desk_executor,desk_lifecycle,desk_audit_delivery;
GRANT EXECUTE ON FUNCTION service_desk.audit_accept(text,uuid,jsonb) TO desk_collector;
INSERT INTO service_desk.schema_version VALUES(12,clock_timestamp());
COMMIT;
