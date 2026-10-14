-- Avoid false disclosure flags for exact text already present in authorized sources.
BEGIN;
CREATE OR REPLACE FUNCTION service_desk.draft_output_safe(t service_desk.read_task, p_body text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE viewers text[] := t.recipients || t.principal_id;
  output text; protected text; marker text; width integer; authorized text[];
BEGIN
  IF p_body IS NULL OR octet_length(p_body) NOT BETWEEN 1 AND 8192 THEN RETURN false; END IF;
  output := lower(regexp_replace(p_body,'[[:space:]]+',' ','g'));
  -- Exact overlap with the current authorized source manifest is not a disclosure.
  -- This matters once public guidance is copied into otherwise private ticket comments.
  WITH sources AS MATERIALIZED (
    SELECT value FROM jsonb_array_elements(service_desk.requester_manifest(t))
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

INSERT INTO service_desk.schema_version(version) VALUES(8);
COMMIT;
