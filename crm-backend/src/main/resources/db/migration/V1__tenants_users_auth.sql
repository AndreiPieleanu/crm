-- Multi-tenancy model: one shared schema, a tenant_id column on every tenant-owned table,
-- and PostgreSQL Row-Level Security (RLS) so the database itself hides other tenants' rows.
--
-- The app sets the current tenant on each connection with set_config('app.tenant_id', ...).
-- When no tenant is set, current_tenant_id() is NULL and every policy matches nothing (fail closed).
--
-- Tables are owned by the migration role (crm_owner). The app connects as ${appRole}, which is not
-- the owner and has no BYPASSRLS, so the policies always apply to it.

CREATE FUNCTION current_tenant_id() RETURNS uuid
    LANGUAGE sql STABLE
AS $$ SELECT nullif(current_setting('app.tenant_id', true), '')::uuid $$;

-- ---------------------------------------------------------------------------
-- Tenants: one row per client company
-- ---------------------------------------------------------------------------
CREATE TABLE tenants (
    id         uuid        PRIMARY KEY,
    name       text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    cui        text        CHECK (cui ~ '^[0-9]{2,10}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants
    USING (id = current_tenant_id())
    WITH CHECK (id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- Users: each user belongs to exactly one tenant. E-mail is unique across the whole system.
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL DEFAULT current_tenant_id() REFERENCES tenants (id) ON DELETE CASCADE,
    email         text        NOT NULL CHECK (email = lower(email) AND length(email) <= 254),
    full_name     text        NOT NULL CHECK (length(full_name) BETWEEN 1 AND 200),
    password_hash text        NOT NULL,
    role          text        NOT NULL CHECK (role IN ('ADMIN', 'USER')),
    enabled       boolean     NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_email_key UNIQUE (email)
);
CREATE INDEX users_tenant_idx ON users (tenant_id);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON users
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- Refresh tokens: only a SHA-256 hash of the token is stored, never the token itself.
-- ---------------------------------------------------------------------------
CREATE TABLE refresh_tokens (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid        NOT NULL DEFAULT current_tenant_id() REFERENCES tenants (id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash bytea       NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id);

ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON refresh_tokens
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- Lookups that must happen before the tenant is known (login, token refresh).
-- SECURITY DEFINER runs them as the owner, so they see all tenants; each returns only the
-- columns needed for authentication, for one exact key. The app role may call them, nothing more.
-- ---------------------------------------------------------------------------
CREATE FUNCTION auth_find_user_by_email(p_email text)
    RETURNS TABLE (id uuid, tenant_id uuid, password_hash text, role text, enabled boolean)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
    SELECT u.id, u.tenant_id, u.password_hash, u.role, u.enabled
    FROM users u
    WHERE u.email = lower(p_email)
$$;

CREATE FUNCTION auth_find_refresh_token(p_hash bytea)
    RETURNS TABLE (id uuid, tenant_id uuid, user_id uuid, expires_at timestamptz, revoked_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = public, pg_temp
AS $$
    SELECT t.id, t.tenant_id, t.user_id, t.expires_at, t.revoked_at
    FROM refresh_tokens t
    WHERE t.token_hash = p_hash
$$;

-- ---------------------------------------------------------------------------
-- Privileges for the app role: only what it needs.
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION auth_find_user_by_email(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_find_refresh_token(bytea) FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO ${appRole};
GRANT EXECUTE ON FUNCTION current_tenant_id() TO ${appRole};
GRANT EXECUTE ON FUNCTION auth_find_user_by_email(text) TO ${appRole};
GRANT EXECUTE ON FUNCTION auth_find_refresh_token(bytea) TO ${appRole};

GRANT SELECT, INSERT, UPDATE ON tenants TO ${appRole};
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO ${appRole};
GRANT SELECT, INSERT, UPDATE, DELETE ON refresh_tokens TO ${appRole};
