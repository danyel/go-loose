-- +goose Up
ALTER TABLE memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE memberships
    ADD CONSTRAINT memberships_role_check
    CHECK (role IN ('owner', 'admin', 'developer', 'operator', 'viewer', 'user'));

ALTER TABLE users
    ADD COLUMN avatar_key text UNIQUE,
    ADD COLUMN avatar bytea,
    ADD COLUMN avatar_content_type text,
    ADD COLUMN avatar_updated_at timestamptz,
    ADD COLUMN name_customized boolean NOT NULL DEFAULT false,
    ADD COLUMN profile_updated_at timestamptz;

-- The picture columns move together so that a key can never address a missing
-- or mismatched image.
ALTER TABLE users
    ADD CONSTRAINT users_avatar_complete CHECK (
        (avatar IS NULL AND avatar_key IS NULL AND avatar_content_type IS NULL AND avatar_updated_at IS NULL)
        OR (avatar IS NOT NULL AND avatar_key IS NOT NULL AND avatar_content_type IS NOT NULL AND avatar_updated_at IS NOT NULL)
    );

ALTER TABLE users
    ADD CONSTRAINT users_avatar_content_type_known CHECK (
        avatar_content_type IS NULL OR avatar_content_type IN ('image/jpeg', 'image/png', 'image/gif')
    );

-- +goose Down
UPDATE memberships SET role = 'viewer' WHERE role IN ('developer', 'operator', 'user');

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_avatar_content_type_known,
    DROP CONSTRAINT IF EXISTS users_avatar_complete;

ALTER TABLE users
    DROP COLUMN IF EXISTS profile_updated_at,
    DROP COLUMN IF EXISTS name_customized,
    DROP COLUMN IF EXISTS avatar_updated_at,
    DROP COLUMN IF EXISTS avatar_content_type,
    DROP COLUMN IF EXISTS avatar,
    DROP COLUMN IF EXISTS avatar_key;

ALTER TABLE memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE memberships
    ADD CONSTRAINT memberships_role_check CHECK (role IN ('owner', 'admin', 'viewer'));