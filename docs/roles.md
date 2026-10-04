# Roles and capabilities

Every tenant role maps to a fixed set of capabilities in `internal/role`. The console reads the capability list from the server instead of hardcoding role names, and store queries pass `role.Grants(...)` into SQL so authorization and rendering cannot drift apart.

## Capability matrix

| Capability | owner | admin | developer | operator | viewer | user |
| --- | --- | --- | --- | --- | --- | --- |
| `console.read` | yes | yes | yes | yes | yes | no |
| `applications.manage` | yes | yes | yes | no | no | no |
| `keys.manage` | yes | yes | yes | yes | no | no |
| `contracts.manage` | yes | yes | yes | yes | no | no |
| `users.manage` | yes | yes | no | no | no | no |
| `profile.edit` | yes | yes | yes | yes | yes | yes |

Intended use:

- **owner** — full control of the tenant, including role assignment.
- **admin** — manages applications, keys, contracts, and members.
- **developer** — ships service contracts and API keys, but cannot change membership.
- **operator** — runs existing applications: rotates keys and imports contracts.
- **viewer** — read-only console access.
- **user** — self-service only. No console access; the session lands on `/profile`.

`user` members without any tenant membership still see the waiting room. Those with a membership are redirected from `/` to `/profile`, because the dashboard requires `console.read`.

## Where the checks live

Store methods enforce capabilities inside SQL (`role = ANY($n)` with a text array) or inside the same transaction as the write. The server additionally filters and labels UI controls with `role.Allows`. Both layers read the same matrix, so adding a capability or a role is a one-line change in `internal/role/role.go`.

`role.Role` values are also validated by a database check constraint on `memberships.role`, so an unknown role cannot be stored even if a caller bypasses the Go layer.

New roles must be added to the check constraint in a new migration as well as to the matrix; existing deployments keep the constraint in `internal/database/migrations/0005_roles_and_profile.sql` for historical reasons.

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

A user with no membership in the application's tenant still authenticates, but the role falls back to `user` with only `profile.edit`.