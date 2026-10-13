-- PostgreSQL foundation only. Future workflow tables require later migrations.
-- Apply to an empty disposable database as the migration owner, never as the agent.
BEGIN;
CREATE SCHEMA service_desk;
CREATE TABLE service_desk.schema_version (
    version integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE service_desk.principal (
    id text PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('human', 'workload')),
    department text NOT NULL,
    manager_id text REFERENCES service_desk.principal(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE service_desk.document (
    id text PRIMARY KEY,
    version integer NOT NULL CHECK (version > 0),
    classification text NOT NULL CHECK (classification IN ('public', 'team', 'hr', 'privileged')),
    title text NOT NULL,
    body text NOT NULL
);
CREATE TABLE service_desk.document_reader (
    document_id text NOT NULL REFERENCES service_desk.document(id),
    principal_id text NOT NULL REFERENCES service_desk.principal(id),
    PRIMARY KEY (document_id, principal_id)
);
CREATE TABLE service_desk.resource_group (
    id text PRIMARY KEY,
    risk text NOT NULL CHECK (risk IN ('standard', 'sensitive')),
    owner_id text NOT NULL REFERENCES service_desk.principal(id)
);
REVOKE ALL ON SCHEMA service_desk FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA service_desk FROM PUBLIC;
INSERT INTO service_desk.schema_version(version) VALUES (1);
COMMIT;
