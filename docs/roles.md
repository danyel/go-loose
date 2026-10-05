# Roles, permissions, and profiles

Authorization is database-driven. Permissions and roles are rows, not Go constants, so a tenant can define its own vocabulary without a code change or a migration.

## Data model

- `permissions` is the closed vocabulary. Every row carries a `name`, a `label`, a `description`, and an `is_system` flag. System permissions cannot be edited or deleted.
- `roles` holds the roles. A `NULL tenant_id` marks a built-in role that every tenant sees and nobody may modify. A custom role belongs to exactly one tenant.
- `role_permissions` joins roles to permissions.
- `memberships.role_id` points at a role row. The older `memberships.role` text column was dropped in `0006_database_roles.sql`.

Nine permissions ship as system rows:

| Permission | Label |
| --- | --- |
| `tenants.manage` | Manage tenants |
| `roles.manage` | Manage roles |
| `users.manage` | Manage members |
| `applications.manage` | Manage applications |
| `keys.manage` | Manage API keys |
| `contracts.manage` | Manage contracts |
| `users.read` | Read members |
| `console.read` | Read console |
| `profile.edit` | Edit own profile |

A tenant may add further permission names. They are grantable and reported through `/connect/userinfo`, but the console does not enforce them.

## Built-in roles

`0006_database_roles.sql` seeds these six roles. Note that `developer` and `operator` hold `users.manage`: any tenant member who runs the console can maintain their own tenant's members. Minting roles stays with `owner` and `admin` through `roles.manage`, because defining privilege is the operation that actually escalates it.

| Permission | owner | admin | developer | operator | viewer | user |
| --- | --- | --- | --- | --- | --- | --- |
| `console.read` | yes | yes | yes | yes | yes | no |
| `users.read` | yes | yes | yes | yes | yes | no |
| `applications.manage` | yes | yes | yes | no | no | no |
| `keys.manage` | yes | yes | yes | yes | no | no |
| `contracts.manage` | yes | yes | yes | yes | no | no |
| `users.manage` | yes | yes | yes | yes | no | no |
| `roles.manage` | yes | yes | no | no | no | no |
| `tenants.manage` | yes | no | no | no | no | no |
| `profile.edit` | yes | yes | yes | yes | yes | yes |

`user` members have no `console.read`, so a session that lands on `/` is redirected to `/profile`. A `user` with no membership at all still sees the waiting room.

## Managing roles

`/roles` is the console page. The API is:

| Route | Purpose |
| --- | --- |
| `GET /api/v1/roles` | List roles with their permissions and member counts |
| `POST /api/v1/roles` | Create a custom role for one tenant |
| `PUT /api/v1/roles/{id}` | Rename a role or change its permissions |
| `DELETE /api/v1/roles/{id}` | Delete a custom role |
| `GET /api/v1/permissions` | List the permission catalog |
| `POST /api/v1/permissions` | Add a permission to the catalog |
| `DELETE /api/v1/permissions/{name}` | Remove an unused permission |

Two rules keep this from becoming a privilege-escalation hole:

- **Assignability is a subset rule.** A role is offered as `assignable` only when every permission it grants is one the requesting administrator already holds. `ListRoles` computes this per caller, so managing members can never hand out more authority than the administrator has.
- **Roles in use cannot be deleted.** `memberships.role_id` is `ON DELETE RESTRICT` and `DeleteRole` returns `ErrRoleInUse`, so a role cannot be pulled out from under somebody. Built-in roles are likewise undeletable.

`role_permissions.permission` is a foreign key onto `permissions.name`, so a role cannot reference a capability that is not in the catalog.

## Go side

`internal/role` holds only the permission vocabulary used to build the seed data and to keep the Go and SQL spellings in step. It intentionally has no role-to-permission matrix: that mapping lives in the database, so queries resolve a member's real capabilities with a join on `role_permissions` rather than against a hardcoded list.

Store methods enforce capabilities in SQL inside the same transaction as the write, so a request cannot pass a handler check and then fail, or the reverse.

## Display names and profile pictures

Every management session can open `/profile` and set a display name and a picture, independent of tenant role.

Setting the display name sets `name_customized`, which stops the identity provider from overwriting it on the next login. The row is still matched by email on every login, so customization never breaks sign-in.

Pictures are stored as bytes in PostgreSQL under a random 256-bit key and served from the public `GET /api/v1/avatars/{key}` route. The URL is unguessable and carries no user identity, so applications can embed it directly:

```html
<img src="https://loose.example.com/api/v1/avatars/kZ3..." alt="Ada Lovelace" width="64" height="64">
```

Accepted formats are JPEG, PNG, and GIF, up to 2 MiB and 4096 by 4096 pixels. Replacing a picture issues a new key and retires the old one, so cached images never go stale and revoked URLs stop resolving.

## Clients

`/connect/token` and `/connect/userinfo` return the caller's `role`, `permissions`, and absolute `avatar_url`, resolved against the tenant that owns the application. `client.User.Can` exposes the same checks to Go code, so a client can adapt its UI without duplicating the vocabulary.

`avatar_url` is public by design and is an empty string when no picture is set. A user with no membership in the application's tenant still authenticates and falls back to the built-in `user` role, whose only permission is `profile.edit`.