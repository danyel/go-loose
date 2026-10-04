-- +goose Up
-- Roles become rows so a tenant can define its own. A NULL tenant_id marks a
-- built-in role: every tenant sees it and nobody may edit or delete it.
CREATE TABLE roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE,
    slug text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    description text NOT NULL DEFAULT '',
    is_system boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    -- Custom roles belong to exactly one tenant; built-in roles to none.
    CONSTRAINT roles_scope CHECK (
        (is_system AND tenant_id IS NULL) OR (NOT is_system AND tenant_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX roles_system_slug_unique ON roles (slug) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX roles_tenant_slug_unique ON roles (tenant_id, slug) WHERE tenant_id IS NOT NULL;

-- The permission vocabulary is closed, so keep this list in step with the
-- constants in internal/role.
CREATE TABLE role_permissions (
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission text NOT NULL CHECK (permission IN (
        'console.read', 'users.read', 'applications.manage', 'keys.manage',
        'contracts.manage', 'users.manage', 'roles.manage', 'tenants.manage',
        'profile.edit')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission)
);

INSERT INTO roles (slug, name, description, is_system) VALUES
    ('owner', 'Owner', 'Full control of the tenant, including roles, members, and tenant settings.', true),
    ('admin', 'Administrator', 'Manages applications, credentials, contracts, members, and roles.', true),
    ('developer', 'Developer', 'Manages applications, credentials, contracts, and members.', true),
    ('operator', 'Operator', 'Issues and revokes credentials, imports contracts, and manages members.', true),
    ('viewer', 'Viewer', 'Reads the console without changing anything.', true),
    ('user', 'User', 'Self-service member with no console access.', true);

-- Seed what used to be the Go matrix. developer and operator join owner and
-- admin in holding users.manage so that any tenant member who runs the console
-- can maintain their own tenant's members. roles.manage stays with owner and
-- admin: minting roles is what defines privilege in the first place.
INSERT INTO role_permissions (role_id, permission)
SELECT r.id, granted.permission
FROM (VALUES
    ('owner', ARRAY[
        'console.read', 'users.read', 'applications.manage', 'keys.manage',
        'contracts.manage', 'users.manage', 'roles.manage', 'tenants.manage',
        'profile.edit']),
    ('admin', ARRAY[
        'console.read', 'users.read', 'applications.manage', 'keys.manage',
        'contracts.manage', 'users.manage', 'roles.manage', 'profile.edit']),
    ('developer', ARRAY[
        'console.read', 'users.read', 'applications.manage', 'keys.manage',
        'contracts.manage', 'users.manage', 'profile.edit']),
    ('operator', ARRAY[
        'console.read', 'users.read', 'keys.manage', 'contracts.manage',
        'users.manage', 'profile.edit']),
    ('viewer', ARRAY['console.read', 'users.read', 'profile.edit']),
    ('user', ARRAY['profile.edit'])
) AS seed(slug, permissions)
JOIN roles r ON r.slug = seed.slug AND r.tenant_id IS NULL
CROSS JOIN LATERAL unnest(seed.permissions) AS granted(permission);

-- Point every membership at a role row. RESTRICT rather than CASCADE so that a
-- role still held by somebody cannot be deleted out from under them.
ALTER TABLE memberships ADD COLUMN role_id uuid REFERENCES roles(id) ON DELETE RESTRICT;

UPDATE memberships m SET role_id = r.id
FROM roles r
WHERE r.tenant_id IS NULL AND r.slug = m.role;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM memberships WHERE role_id IS NULL) THEN
        RAISE EXCEPTION 'cannot migrate memberships: a membership names a role that was never seeded';
    END IF;
END
$$;

ALTER TABLE memberships ALTER COLUMN role_id SET NOT NULL;
ALTER TABLE memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE memberships DROP COLUMN role;

-- +goose Down
ALTER TABLE memberships ADD COLUMN role text;

UPDATE memberships m SET role = r.slug
FROM roles r
WHERE r.id = m.role_id AND r.is_system;

-- Custom roles have no equivalent in the old fixed vocabulary.
UPDATE memberships SET role = 'viewer' WHERE role IS NULL;

ALTER TABLE memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE memberships
    ADD CONSTRAINT memberships_role_check
    CHECK (role IN ('owner', 'admin', 'developer', 'operator', 'viewer', 'user'));
ALTER TABLE memberships ALTER COLUMN role SET NOT NULL;
ALTER TABLE memberships DROP COLUMN role_id;

DROP TABLE role_permissions;
DROP TABLE roles;
