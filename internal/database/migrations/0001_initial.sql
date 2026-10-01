-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    subject text NOT NULL UNIQUE,
    email text NOT NULL,
    display_name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE applications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    slug text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    allowed_hosts text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug)
);

CREATE TABLE api_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    name text NOT NULL,
    prefix text NOT NULL,
    secret_hash bytea NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    expires_at timestamptz,
    last_used_at timestamptz,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE INDEX api_keys_lookup_idx ON api_keys(secret_hash) WHERE status = 'active';
CREATE INDEX api_keys_application_idx ON api_keys(application_id);

CREATE TABLE openapi_contracts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    version text NOT NULL,
    source_url text,
    document jsonb NOT NULL,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE contract_endpoints (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    contract_id uuid NOT NULL REFERENCES openapi_contracts(id) ON DELETE CASCADE,
    method text NOT NULL,
    path text NOT NULL,
    operation_id text NOT NULL DEFAULT '',
    UNIQUE (contract_id, method, path)
);

CREATE TABLE authorization_events (
    id bigserial PRIMARY KEY,
    tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL,
    application_id uuid REFERENCES applications(id) ON DELETE SET NULL,
    api_key_id uuid REFERENCES api_keys(id) ON DELETE SET NULL,
    method text NOT NULL,
    path text NOT NULL,
    host text NOT NULL,
    allowed boolean NOT NULL,
    reason text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX authorization_events_occurred_idx ON authorization_events(occurred_at DESC);

-- +goose Down
DROP TABLE IF EXISTS authorization_events;
DROP TABLE IF EXISTS contract_endpoints;
DROP TABLE IF EXISTS openapi_contracts;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS applications;
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;
