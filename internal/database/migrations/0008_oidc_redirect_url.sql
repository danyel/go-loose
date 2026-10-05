-- +goose Up
ALTER TABLE installation_settings ADD COLUMN oidc_redirect_url text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE installation_settings DROP COLUMN IF EXISTS oidc_redirect_url;