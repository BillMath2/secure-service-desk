-- Admission applies to every task creation path, independently of browser sessions.
BEGIN;
CREATE TABLE service_desk.task_admission_policy (
  singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
  user_active integer NOT NULL CHECK(user_active BETWEEN 1 AND 4),
  global_active integer NOT NULL CHECK(global_active BETWEEN user_active AND 32),
  user_minute integer NOT NULL CHECK(user_minute BETWEEN 1 AND 20),
  global_minute integer NOT NULL CHECK(global_minute BETWEEN user_minute AND 100),
  lock_version bigint NOT NULL DEFAULT 0
);
INSERT INTO service_desk.task_admission_policy
  (user_active,global_active,user_minute,global_minute) VALUES(4,32,20,100);
REVOKE ALL ON service_desk.task_admission_policy FROM PUBLIC;

-- Existing tasks conservatively count as newly admitted when upgrading.
ALTER TABLE service_desk.read_task ADD COLUMN created_at timestamptz
  NOT NULL DEFAULT clock_timestamp();
CREATE INDEX task_admission_time ON service_desk.read_task(created_at);
CREATE INDEX task_admission_principal_time ON service_desk.read_task(principal_id,created_at);
CREATE INDEX task_admission_active ON service_desk.read_task(deadline) WHERE active;

CREATE FUNCTION service_desk.enforce_task_admission() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,service_desk AS $$
DECLARE policy service_desk.task_admission_policy; now_at timestamptz;
  active_user bigint; active_global bigint; recent_user bigint; recent_global bigint;
BEGIN
  -- A real row update serializes admissions globally and forces stale repeatable-read /
  -- serializable transactions to abort, rather than count an obsolete snapshot.
  UPDATE service_desk.task_admission_policy SET lock_version=lock_version+1
    WHERE singleton RETURNING * INTO STRICT policy;
  now_at := clock_timestamp();
  SELECT count(*) FILTER (WHERE active AND deadline>now_at AND principal_id=NEW.principal_id),
    count(*) FILTER (WHERE active AND deadline>now_at),
    count(*) FILTER (WHERE created_at>now_at-interval '1 minute'
      AND principal_id=NEW.principal_id),
    count(*) FILTER (WHERE created_at>now_at-interval '1 minute')
    INTO active_user,active_global,recent_user,recent_global
    FROM service_desk.read_task
    WHERE (active AND deadline>now_at) OR created_at>now_at-interval '1 minute';
  IF active_user>=policy.user_active OR active_global>=policy.global_active
    OR recent_user>=policy.user_minute OR recent_global>=policy.global_minute THEN
    RAISE EXCEPTION 'Task admission exhausted'
      USING ERRCODE='P0001', CONSTRAINT='task_admission_limit';
  END IF;
  -- Caller-supplied timestamps cannot age a task out of admission accounting.
  NEW.created_at := now_at;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION service_desk.enforce_task_admission() FROM PUBLIC;
CREATE TRIGGER enforce_task_admission BEFORE INSERT ON service_desk.read_task
  FOR EACH ROW EXECUTE FUNCTION service_desk.enforce_task_admission();
INSERT INTO service_desk.schema_version(version) VALUES(10);
COMMIT;
