-- +goose Up
ALTER TABLE applications
    ADD COLUMN client_id text NOT NULL UNIQUE DEFAULT ('glc_' || encode(gen_random_bytes(18), 'hex')),
    ADD COLUMN client_secret_hash bytea,
    ADD COLUMN redirect_uris text[] NOT NULL DEFAULT '{}';

CREATE UNIQUE INDEX users_email_unique_idx ON users (lower(email));

CREATE TABLE user_application_access (
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    granted_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (application_id, user_id)
);

INSERT INTO user_application_access(application_id, user_id, granted_by)
SELECT a.id, m.user_id, m.user_id
FROM applications a
JOIN memberships m ON m.tenant_id = a.tenant_id
ON CONFLICT DO NOTHING;

CREATE TABLE client_authorization_codes (
    code_hash bytea PRIMARY KEY,
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE client_user_sessions (
    token_hash bytea PRIMARY KEY,
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX client_user_sessions_user_idx ON client_user_sessions(user_id);
CREATE INDEX client_authorization_codes_expiry_idx ON client_authorization_codes(expires_at);

-- +goose Down
DROP TABLE IF EXISTS client_user_sessions;
DROP TABLE IF EXISTS client_authorization_codes;
DROP TABLE IF EXISTS user_application_access;
DROP INDEX IF EXISTS users_email_unique_idx;
ALTER TABLE applications
    DROP COLUMN IF EXISTS redirect_uris,
    DROP COLUMN IF EXISTS client_secret_hash,
    DROP COLUMN IF EXISTS client_id;
