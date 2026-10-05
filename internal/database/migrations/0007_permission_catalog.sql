-- +goose Up
-- Permissions become rows so the catalog can be extended without a migration.
-- The nine names the application enforces in SQL are seeded here; a tenant may
-- add further names, which are grantable and reported through /connect/userinfo
-- but are not checked by the console itself.
CREATE TABLE permissions (
    name text PRIMARY KEY CHECK (name ~ '^[a-z0-9][a-z0-9]*(?:[.-][a-z0-9]+)*$'),
    label text NOT NULL CHECK (length(btrim(label)) BETWEEN 1 AND 100),
    description text NOT NULL DEFAULT '',
    is_system boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO permissions (name, label, description, is_system) VALUES
    ('tenants.manage',    'Manage tenants',    'Create tenants and administer the installation.', true),
    ('roles.manage',      'Manage roles',      'Create and edit the roles of this tenant.', true),
    ('users.manage',      'Manage members',    'Invite members and change their roles and application grants.', true),
    ('applications.manage', 'Manage applications', 'Register applications and configure client credentials.', true),
    ('keys.manage',       'Manage API keys',   'Issue and revoke API keys.', true),
    ('contracts.manage',  'Manage contracts',  'Import OpenAPI contracts and their endpoints.', true),
    ('users.read',        'Read members',      'List the members of a tenant and the roles they hold.', true),
    ('console.read',      'Read console',      'Open the management console and pick tenants.', true),
    ('profile.edit',      'Edit own profile',  'Change one''s own display name and picture.', true);

-- The closed list becomes a foreign key, so a role can no longer be granted a
-- capability that is not in the catalog. Granting one is now a matter of
-- inserting the permission first rather than editing a check constraint.
ALTER TABLE role_permissions DROP CONSTRAINT role_permissions_permission_check;
ALTER TABLE role_permissions
    ADD CONSTRAINT role_permissions_permission_fkey
    FOREIGN KEY (permission) REFERENCES permissions(name) ON DELETE RESTRICT;

-- +goose Down
DELETE FROM role_permissions WHERE permission NOT IN (
    'tenants.manage', 'roles.manage', 'users.manage', 'applications.manage',
    'keys.manage', 'contracts.manage', 'users.read', 'console.read', 'profile.edit'
);

ALTER TABLE role_permissions DROP CONSTRAINT role_permissions_permission_fkey;
ALTER TABLE role_permissions
    ADD CONSTRAINT role_permissions_permission_check CHECK (permission IN (
        'tenants.manage', 'roles.manage', 'users.manage', 'applications.manage',
        'keys.manage', 'contracts.manage', 'users.read', 'console.read', 'profile.edit'
    ));

DROP TABLE permissions;