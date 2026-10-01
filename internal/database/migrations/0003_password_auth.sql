-- +goose Up
ALTER TABLE users
    ADD COLUMN password_hash text,
    ADD COLUMN password_changed_at timestamptz;

CREATE TABLE user_login_events (
    id bigserial PRIMARY KEY,
    user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    email text NOT NULL,
    remote_address text NOT NULL,
    successful boolean NOT NULL,
    reason text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX user_login_events_occurred_idx ON user_login_events(occurred_at DESC);
CREATE INDEX user_login_events_email_idx ON user_login_events(lower(email), occurred_at DESC);

-- +goose Down
DROP TABLE IF EXISTS user_login_events;
ALTER TABLE users
    DROP COLUMN IF EXISTS password_changed_at,
    DROP COLUMN IF EXISTS password_hash;
