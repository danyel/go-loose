-- +goose Up
CREATE TABLE installation_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    installed_at timestamptz NOT NULL DEFAULT now(),
    oidc_issuer text NOT NULL,
    oidc_client_id text NOT NULL,
    oidc_client_secret_ciphertext bytea NOT NULL,
    seeded_demo boolean NOT NULL DEFAULT false
);

CREATE TABLE system_administrators (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS system_administrators;
DROP TABLE IF EXISTS installation_settings;
