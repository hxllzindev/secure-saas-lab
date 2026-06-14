CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
    CREATE ROLE aegis_app LOGIN PASSWORD 'aegis_app_dev' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS lab;

CREATE TABLE tenants (
  id text PRIMARY KEY,
  name text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name text NOT NULL,
  email text NOT NULL UNIQUE,
  role text NOT NULL CHECK (role IN ('admin', 'analyst')),
  mfa_code text NOT NULL,
  password_salt text NOT NULL,
  password_hash text NOT NULL,
  password_iterations integer NOT NULL CHECK (password_iterations >= 100000),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE invoices (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  customer text NOT NULL,
  amount numeric(14,2) NOT NULL CHECK (amount >= 0),
  status text NOT NULL CHECK (status IN ('paid', 'pending', 'overdue')),
  due_date date NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE notes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  author text NOT NULL,
  content text NOT NULL CHECK (char_length(content) BETWEEN 1 AND 2000),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id text REFERENCES tenants(id) ON DELETE SET NULL,
  action text NOT NULL,
  mode text NOT NULL CHECK (mode IN ('secure', 'vulnerable')),
  actor text,
  email text,
  ip text,
  reason text,
  resource_id text,
  technique_id text,
  technique_name text,
  severity text NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'low', 'medium', 'high')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE refresh_sessions (
  token_hash text PRIMARY KEY,
  family_id uuid NOT NULL,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  replaced_by_hash text,
  user_agent text,
  ip text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX invoices_tenant_idx ON invoices (tenant_id, due_date DESC);
CREATE INDEX notes_tenant_idx ON notes (tenant_id, created_at DESC);
CREATE INDEX audit_events_tenant_idx ON audit_events (tenant_id, created_at DESC);
CREATE INDEX refresh_sessions_family_idx ON refresh_sessions (family_id);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE refresh_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY users_tenant_isolation ON users
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY invoices_tenant_isolation ON invoices
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY notes_tenant_isolation ON notes
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY audit_tenant_isolation ON audit_events
  USING (
    tenant_id = current_setting('app.tenant_id', true)
    AND current_setting('app.user_role', true) = 'admin'
  );

CREATE POLICY refresh_session_isolation ON refresh_sessions
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE OR REPLACE FUNCTION auth.lookup_user(input_email text)
RETURNS TABLE (
  id text,
  tenant_id text,
  tenant_name text,
  name text,
  email text,
  role text,
  mfa_code text,
  password_salt text,
  password_hash text,
  password_iterations integer
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT u.id, u.tenant_id, t.name, u.name, u.email, u.role, u.mfa_code,
         u.password_salt, u.password_hash, u.password_iterations
  FROM users u
  JOIN tenants t ON t.id = u.tenant_id
  WHERE u.email = lower(trim(input_email))
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION auth.lookup_user_by_id(input_id text)
RETURNS TABLE (
  id text,
  tenant_id text,
  tenant_name text,
  name text,
  email text,
  role text,
  mfa_code text,
  password_salt text,
  password_hash text,
  password_iterations integer
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT u.id, u.tenant_id, t.name, u.name, u.email, u.role, u.mfa_code,
         u.password_salt, u.password_hash, u.password_iterations
  FROM users u
  JOIN tenants t ON t.id = u.tenant_id
  WHERE u.id = input_id
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION lab.lookup_invoice_unsafe(input_id text)
RETURNS SETOF invoices
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT * FROM invoices WHERE id = input_id LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION auth.write_audit_event(
  input_tenant_id text,
  input_action text,
  input_mode text,
  input_actor text,
  input_email text,
  input_ip text,
  input_reason text,
  input_resource_id text,
  input_technique_id text,
  input_technique_name text,
  input_severity text
)
RETURNS SETOF audit_events
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  INSERT INTO audit_events
    (tenant_id, action, mode, actor, email, ip, reason, resource_id, technique_id, technique_name, severity)
  VALUES
    (input_tenant_id, input_action, input_mode, input_actor, input_email, input_ip,
     input_reason, input_resource_id, input_technique_id, input_technique_name, input_severity)
  RETURNING *;
$$;

CREATE OR REPLACE FUNCTION auth.create_refresh_session(
  input_token_hash text,
  input_family_id uuid,
  input_user_id text,
  input_tenant_id text,
  input_expires_at timestamptz,
  input_user_agent text,
  input_ip text
)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  INSERT INTO refresh_sessions
    (token_hash, family_id, user_id, tenant_id, expires_at, user_agent, ip)
  VALUES
    (input_token_hash, input_family_id, input_user_id, input_tenant_id,
     input_expires_at, input_user_agent, input_ip);
$$;

CREATE OR REPLACE FUNCTION auth.lookup_refresh_session(input_token_hash text)
RETURNS TABLE (
  token_hash text,
  family_id uuid,
  user_id text,
  tenant_id text,
  expires_at timestamptz,
  revoked_at timestamptz,
  replaced_by_hash text
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT r.token_hash, r.family_id, r.user_id, r.tenant_id,
         r.expires_at, r.revoked_at, r.replaced_by_hash
  FROM refresh_sessions r
  WHERE r.token_hash = input_token_hash
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION auth.rotate_refresh_session(
  input_old_hash text,
  input_new_hash text,
  input_family_id uuid,
  input_user_id text,
  input_tenant_id text,
  input_expires_at timestamptz,
  input_user_agent text,
  input_ip text
)
RETURNS TABLE (status text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  current_session refresh_sessions%ROWTYPE;
BEGIN
  SELECT * INTO current_session
  FROM refresh_sessions
  WHERE token_hash = input_old_hash
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN QUERY SELECT 'missing'::text;
    RETURN;
  END IF;

  IF current_session.revoked_at IS NOT NULL OR current_session.expires_at <= now() THEN
    UPDATE refresh_sessions
    SET revoked_at = COALESCE(revoked_at, now())
    WHERE family_id = current_session.family_id;
    RETURN QUERY SELECT 'reused'::text;
    RETURN;
  END IF;

  UPDATE refresh_sessions
  SET revoked_at = now(), replaced_by_hash = input_new_hash
  WHERE token_hash = input_old_hash;

  INSERT INTO refresh_sessions
    (token_hash, family_id, user_id, tenant_id, expires_at, user_agent, ip)
  VALUES
    (input_new_hash, input_family_id, input_user_id, input_tenant_id,
     input_expires_at, input_user_agent, input_ip);

  RETURN QUERY SELECT 'rotated'::text;
END;
$$;

CREATE OR REPLACE FUNCTION auth.revoke_refresh_family(input_family_id uuid)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  UPDATE refresh_sessions
  SET revoked_at = COALESCE(revoked_at, now())
  WHERE family_id = input_family_id;
$$;

REVOKE ALL ON FUNCTION auth.lookup_user(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth.lookup_user_by_id(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION lab.lookup_invoice_unsafe(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth.write_audit_event(text,text,text,text,text,text,text,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth.create_refresh_session(text,uuid,text,text,timestamptz,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth.lookup_refresh_session(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth.rotate_refresh_session(text,text,uuid,text,text,timestamptz,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth.revoke_refresh_family(uuid) FROM PUBLIC;

GRANT CONNECT ON DATABASE secure_saas TO aegis_app;
GRANT USAGE ON SCHEMA public, auth, lab TO aegis_app;
GRANT SELECT ON tenants, users, invoices, notes, audit_events TO aegis_app;
GRANT INSERT ON notes TO aegis_app;
GRANT EXECUTE ON FUNCTION auth.lookup_user(text) TO aegis_app;
GRANT EXECUTE ON FUNCTION auth.lookup_user_by_id(text) TO aegis_app;
GRANT EXECUTE ON FUNCTION lab.lookup_invoice_unsafe(text) TO aegis_app;
GRANT EXECUTE ON FUNCTION auth.write_audit_event(text,text,text,text,text,text,text,text,text,text,text) TO aegis_app;
GRANT EXECUTE ON FUNCTION auth.create_refresh_session(text,uuid,text,text,timestamptz,text,text) TO aegis_app;
GRANT EXECUTE ON FUNCTION auth.lookup_refresh_session(text) TO aegis_app;
GRANT EXECUTE ON FUNCTION auth.rotate_refresh_session(text,text,uuid,text,text,timestamptz,text,text) TO aegis_app;
GRANT EXECUTE ON FUNCTION auth.revoke_refresh_family(uuid) TO aegis_app;
