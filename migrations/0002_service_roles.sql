-- Database-local object privileges assigned to cluster-local NOLOGIN group roles.
-- Bootstrap credentials and LOGIN roles are provisioned separately, never committed.
BEGIN;
CREATE ROLE desk_knowledge NOLOGIN;
CREATE ROLE desk_tickets NOLOGIN;
CREATE ROLE desk_access NOLOGIN;
CREATE ROLE desk_executor NOLOGIN;
CREATE ROLE desk_lifecycle NOLOGIN;
CREATE ROLE desk_audit_writer NOLOGIN;
GRANT USAGE ON SCHEMA service_desk TO desk_knowledge;
GRANT SELECT ON service_desk.document, service_desk.document_reader,
    service_desk.principal TO desk_knowledge;
-- No agent database role exists. Other roles receive no object grants until their
-- services/tables exist. Knowledge's SQL access is service-level, not end-user RLS;
-- the knowledge service must enforce per-user ACLs before returning any data.
INSERT INTO service_desk.schema_version(version) VALUES (2);
COMMIT;
