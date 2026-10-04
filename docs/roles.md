# Roles and capabilities

A role is a named bundle of permissions. Roles are rows: six built-in ones seeded by migration `0006_database_roles.sql`, plus whatever each tenant defines for itself. `internal/role` no longer holds a matrix — it holds the closed vocabulary of permissions a role may be granted, and the database resolves what a membership actually grants.

```
roles              one row per role. tenant_id NULL means built-in.
role_permissions   (role_id, permission) — what the role grants.
memberships.role_id → roles.id, NOT NULL, ON DELETE RESTRICT
```

## Built-in capability matrix

This is what the migration seeds. It is data, not code: change it with a new migration, not by editing Go.

| Permission | owner | admin | developer | operator | viewer | user |
| --- | --- | --- | --- | --- | --- | --- |
| `tenants.manage` | yes | no | no | no | no | no |
| `roles.manage` | yes | yes | no | no | no | no |
| `users.manage` | yes | yes | yes | yes | no | no |
| `applications.manage` | yes | yes | yes | no | no | no |
| `keys.manage` | yes | yes | yes | yes | no | no |
| `contracts.manage` | yes | yes | yes | yes | no | no |
| `users.read` | yes | yes | yes | yes | yes | no |
| `console.read` | yes | yes | yes | yes | yes | no |
| `profile.edit` | yes | yes | yes | yes | yes | yes |

Intended use:

- **owner** — full control of the tenant, including defining roles and handing them out.
- **admin** — manages applications, keys, contracts, members, and roles.
- **developer** — ships applications, keys, and contracts, and maintains the tenant's members.
- **operator** — runs existing applications and maintains the tenant's members.
- **viewer** — read-only console access.
- **user** — self-service only. No console access; the session lands on `/profile`.

`developer` and `operator` hold `users.manage` so that anyone who runs the console can maintain their own tenant's members. `roles.manage` deliberately stays narrow: defining roles is what defines privilege, so it is not something a member administrator can grant themselves.

`user` members without any tenant membership still see the waiting room. Those with a membership are redirected from `/` to `/profile`, because the dashboard requires `console.read`.

## Tenant-defined roles

`POST /api/v1/roles` creates a role for one tenant. It is visible only in that tenant, and the `/roles` screen lists it beside the built-ins with its permission chips.

Three rules keep this from becoming a privilege-escalation hole:

1. **Roles are scoped.** `roles.tenant_id` is set, and every query that resolves a role filters on the caller's own tenant, so a role id cannot be probed across tenants.
2. **You cannot mint what you do not hold.** Creating or editing a role requires `roles.manage` *and* requires every permission in the role to be one the caller already has. Assigning a role enforces the same subset rule.
3. **A role in use cannot be deleted.** `memberships.role_id` is `ON DELETE RESTRICT`, and `DELETE /api/v1/roles/{id}` reports 409 until the members are moved. Built-in roles are immutable and report 404.

Built-in roles are read only: the store refuses to edit or delete a row with `is_system` set.

## Where the checks live

Tenant-scoped statements resolve the grant through `role_permissions` using one shared predicate, `permissionPredicate` in `internal/store/roles.go`:

```sql
EXISTS (
    SELECT 1
    FROM memberships scoped
    JOIN role_permissions granted ON granted.role_id = scoped.role_id
    WHERE scoped.tenant_id = $1 AND scoped.user_id = $2
      AND granted.permission = $3
)
```

Because the check asks for a permission rather than a role name, a tenant's own role works everywhere a built-in one does without any Go change. The server never decides authorization: `handleStoreError` maps `store.ErrNotFound` to a 404 so a denied write and a missing row are indistinguishable.

`role.Permission` names are also constrained by a check constraint on `role_permissions.permission`, so an unknown capability cannot be stored even if a caller bypasses the Go layer. **Adding a permission therefore needs three edits**: the constant in `internal/role/role.go`, the check constraint and seed in a new migration, and the expected grants in `internal/store/roles_integration_test.go`.

## Display names and profile pictures

Every management session can open `/profile` and set a display name and a profile picture, independent of tenant role.

Setting the display name flags the user as `name_customized`, which stops the identity provider from overwriting it on the next login. The row is still matched by email on every login, so customization never breaks sign-in.

Pictures are stored as bytes in PostgreSQL with a random 256-bit key and served from the public `GET /api/v1/avatars/{key}` route. The URL is unguessable and carries no user identity, so applications can embed it directly:

```html
<img src="https://loose.example.com/api/v1/avatars/kZ3..." alt="Ada Lovelace" width="64" height="64">
```

Accepted formats are JPEG, PNG, and GIF up to 2 MiB and 4096 by 4096 pixels. Replacing a picture issues a new key and retires the old one, so cached images never go stale and revoked URLs stop resolving.

## Clients and permissions

`/connect/token` and `/connect/userinfo` return the caller's `role`, `permissions`, and absolute `avatar_url`, resolved against the tenant that owns the application. `client.User.Can` exposes the same checks to Go code, so a client can adapt its UI without duplicating the matrix.

A user with no membership in the application's tenant still authenticates, but the role falls back to the built-in `user` role with only `profile.edit`.