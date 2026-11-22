-- Contacts: the people and companies each tenant works with.
CREATE TABLE contacts (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid        NOT NULL DEFAULT current_tenant_id() REFERENCES tenants (id) ON DELETE CASCADE,
    first_name   text        NOT NULL CHECK (length(first_name) BETWEEN 1 AND 100),
    last_name    text        CHECK (length(last_name) <= 100),
    email        text        CHECK (length(email) <= 254),
    phone        text        CHECK (length(phone) <= 30),
    company_name text        CHECK (length(company_name) <= 200),
    notes        text        CHECK (length(notes) <= 5000),
    created_by   uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX contacts_tenant_created_idx ON contacts (tenant_id, created_at DESC);

ALTER TABLE contacts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON contacts
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON contacts TO ${appRole};
