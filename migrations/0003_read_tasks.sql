-- Shared read-only task boundary. Only trusted application code creates tasks.
BEGIN;
CREATE ROLE desk_task_creator NOLOGIN;
CREATE ROLE desk_gateway NOLOGIN;
CREATE TABLE service_desk.read_fixture_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton), sha256 text NOT NULL
);
CREATE TABLE service_desk.identity_binding (
    issuer text NOT NULL, subject text NOT NULL,
    principal_id text NOT NULL REFERENCES service_desk.principal(id),
    PRIMARY KEY (issuer, subject)
);
CREATE TABLE service_desk.read_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    version text NOT NULL, max_calls integer NOT NULL CHECK (max_calls BETWEEN 1 AND 12),
    timeout_seconds integer NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 120),
    max_bytes integer NOT NULL CHECK (max_bytes BETWEEN 256 AND 32768)
);
INSERT INTO service_desk.read_policy VALUES (true, 'policy-v1', 12, 120, 32768);
CREATE TABLE service_desk.ticket (
    id text PRIMARY KEY, requester text NOT NULL REFERENCES service_desk.principal(id),
    team text NOT NULL, body text NOT NULL, version integer NOT NULL DEFAULT 1,
    submitted_at timestamptz NOT NULL
);
CREATE TABLE service_desk.ticket_reader (
    ticket_id text NOT NULL REFERENCES service_desk.ticket(id),
    principal_id text NOT NULL REFERENCES service_desk.principal(id),
    PRIMARY KEY(ticket_id, principal_id)
);
CREATE TABLE service_desk.ticket_comment (
    id text PRIMARY KEY, ticket_id text NOT NULL REFERENCES service_desk.ticket(id),
    visibility text NOT NULL CHECK (visibility IN ('requester', 'internal')), body text NOT NULL
);
CREATE TABLE service_desk.comment_reader (
    comment_id text NOT NULL REFERENCES service_desk.ticket_comment(id),
    principal_id text NOT NULL REFERENCES service_desk.principal(id),
    PRIMARY KEY(comment_id, principal_id)
);
ALTER TABLE service_desk.document ADD COLUMN search_vector tsvector
    GENERATED ALWAYS AS (to_tsvector('english', title || ' ' || body)) STORED;
CREATE INDEX document_search_idx ON service_desk.document USING gin(search_vector);

CREATE TABLE service_desk.read_task (
    id uuid PRIMARY KEY, correlation_id uuid NOT NULL,
    issuer text NOT NULL, subject text NOT NULL, principal_id text NOT NULL,
    client_id text NOT NULL CHECK (client_id = 'gateway'),
    ticket_id text NOT NULL REFERENCES service_desk.ticket(id),
    recipients text[] NOT NULL CHECK (cardinality(recipients) > 0),
    capabilities text[] NOT NULL, policy_version text NOT NULL,
    deadline timestamptz NOT NULL, max_calls integer NOT NULL CHECK (max_calls BETWEEN 1 AND 12),
    used_calls integer NOT NULL DEFAULT 0 CHECK (used_calls BETWEEN 0 AND max_calls),
    max_bytes integer NOT NULL, active boolean NOT NULL DEFAULT true,
    FOREIGN KEY (issuer, subject) REFERENCES service_desk.identity_binding(issuer, subject)
);
CREATE TABLE service_desk.read_attempt (
    id uuid PRIMARY KEY, task_id uuid NOT NULL REFERENCES service_desk.read_task(id),
    service text NOT NULL CHECK (service IN ('knowledge', 'tickets', 'gateway')),
    tool text NOT NULL, arguments_hash text NOT NULL,
    state text NOT NULL CHECK (state IN ('reserved', 'consumed', 'finished')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE service_desk.read_audit (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    task_id uuid NOT NULL REFERENCES service_desk.read_task(id), attempt_id uuid,
    correlation_id uuid NOT NULL, operation text NOT NULL, reason text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION service_desk.create_read_task(
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
       ARRAY['read_document', 'search_documents', 'read_ticket'], policy.version,
       clock_timestamp() + make_interval(secs => policy.timeout_seconds),
       policy.max_calls, policy.max_bytes);
    RETURN true;
END $$;

CREATE FUNCTION service_desk.reserve_read_attempt(
    p_id uuid, p_task uuid, p_issuer text, p_subject text, p_service text, p_tool text, p_hash text
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE t service_desk.read_task; reason text := 'ALLOW';
BEGIN
    IF p_service NOT IN ('knowledge', 'tickets', 'gateway') OR NOT (
      pg_has_role(session_user, 'desk_gateway', 'member') OR
      (p_service = 'knowledge' AND pg_has_role(session_user, 'desk_knowledge', 'member')) OR
      (p_service = 'tickets' AND pg_has_role(session_user, 'desk_tickets', 'member'))
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

CREATE FUNCTION service_desk.consume_read_attempt(
    p_id uuid, p_task uuid, p_issuer text, p_subject text, p_service text, p_tool text, p_hash text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE t service_desk.read_task; a service_desk.read_attempt;
BEGIN
    IF NOT ((p_service = 'knowledge' AND pg_has_role(session_user, 'desk_knowledge', 'member')) OR
            (p_service = 'tickets' AND pg_has_role(session_user, 'desk_tickets', 'member')))
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

CREATE FUNCTION service_desk.finish_read_attempt(p_id uuid, p_reason text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, service_desk AS $$
DECLARE a service_desk.read_attempt; t service_desk.read_task;
BEGIN
    IF p_reason NOT IN ('ALLOW', 'TOOL_DENIED', 'SCHEMA_DENIED', 'CATALOG_DENIED',
      'SCOPE_DENIED', 'RESOURCE_DENIED', 'TASK_DENIED', 'TASK_EXPIRED', 'POLICY_STALE',
      'OUTPUT_LIMIT', 'SERVICE_ERROR', 'TIMEOUT') THEN RETURN false; END IF;
    SELECT * INTO a FROM service_desk.read_attempt WHERE id = p_id FOR UPDATE;
    IF NOT FOUND OR a.state = 'finished' OR NOT (
      (a.service = 'knowledge' AND pg_has_role(session_user, 'desk_knowledge', 'member')) OR
      (a.service = 'tickets' AND pg_has_role(session_user, 'desk_tickets', 'member')) OR
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

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA service_desk FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA service_desk FROM PUBLIC;
GRANT USAGE ON SCHEMA service_desk TO desk_task_creator, desk_gateway, desk_tickets;
GRANT EXECUTE ON FUNCTION service_desk.create_read_task(uuid,uuid,text,text,text,text)
    TO desk_task_creator;
GRANT EXECUTE ON FUNCTION service_desk.reserve_read_attempt(uuid,uuid,text,text,text,text,text)
    TO desk_gateway, desk_knowledge, desk_tickets;
GRANT EXECUTE ON FUNCTION service_desk.consume_read_attempt(uuid,uuid,text,text,text,text,text)
    TO desk_knowledge, desk_tickets;
GRANT EXECUTE ON FUNCTION service_desk.finish_read_attempt(uuid,text)
    TO desk_gateway, desk_knowledge, desk_tickets;
GRANT SELECT ON service_desk.ticket, service_desk.ticket_reader, service_desk.ticket_comment,
    service_desk.comment_reader, service_desk.principal TO desk_tickets;
-- Knowledge also checks that the task's ticket is still visible before any source read.
GRANT SELECT ON service_desk.ticket_reader, service_desk.principal TO desk_knowledge;
INSERT INTO service_desk.schema_version(version) VALUES (3);
COMMIT;
