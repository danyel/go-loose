# Operations

## First-run installer

New deployments need only PostgreSQL, the public URL settings, and a stable session secret. Open `/install` to configure Google SSO and optional Guess demo data. See [First-run installation and demo data](installation.md).

The first Google SSO user is claimed as system administrator. All later SSO users remain in the waiting room until that administrator grants tenant membership and application access.

## OIDC / SSO

Register an OIDC confidential web client with this callback:

```text
https://<go-loose-host>/auth/callback
```

The web installer is preferred. Environment configuration remains available for existing or fully automated deployments:

```dotenv
GO_LOOSE_BASE_URL=https://auth.example.com
GO_LOOSE_AUTH_DOMAIN=auth.example.com
GO_LOOSE_OIDC_ISSUER=https://id.example.com/realms/platform
GO_LOOSE_OIDC_CLIENT_ID=go-loose
GO_LOOSE_OIDC_CLIENT_SECRET=<from-secret-manager>
GO_LOOSE_OIDC_REDIRECT_URL=https://auth.example.com/auth/callback
GO_LOOSE_ALLOWED_EMAIL_DOMAINS=example.com
GO_LOOSE_DEV_LOGIN=false
```

System-administrator SSO is served on `https://auth.example.com`. Client applications and tenant password login use `https://<tenant>.auth.example.com`; configure wildcard DNS and TLS for `*.auth.example.com`.

Database authentication is controlled by `GO_LOOSE_LOCAL_LOGIN`. It may remain enabled for seeded or invited users without creating a bootstrap account. Set `GO_LOOSE_LOCAL_ADMIN_PASSWORD` only when compatibility bootstrap behavior is explicitly required, and provide it through a secret manager.

The provider must return `sub`, `email`, and preferably `name` claims.

## Migrations

Migration files live in `internal/database/migrations` and are embedded into the binary. Files run lexicographically once, in individual transactions.

A migration run holds a session-level advisory lock, so several replicas may start at the same time against one database. Without it the run races with itself: PostgreSQL's `CREATE TABLE IF NOT EXISTS` is not race free and can fail with a duplicate `pg_type` row, and two replicas can try to apply the same file. The second replica waits and then finds the work already recorded.

Create upgrades with an immutable numbered file:

```text
0002_membership_invitations.sql
```

Use this structure:

```sql
-- +goose Up
CREATE TABLE membership_invitations (...);

-- +goose Down
DROP TABLE membership_invitations;
```

The built-in runner applies only the `Up` section. Down sections document rollback intent but are never run automatically. Never edit an applied migration; create a new one. Prefer backward-compatible expansion first, deploy code that understands both shapes, then remove old fields in a later release.

Back up the database before production upgrades. Restore and test backups regularly. Startup fails if a migration fails, preventing the application from running against a partially upgraded schema.

## Production checklist

- TLS terminates at a trusted ingress and forwards the original host.
- `GO_LOOSE_BASE_URL` is the exact HTTPS browser origin.
- Session and OIDC secrets come from a secret manager.
- Demo users are not seeded, or every demo credential is removed/rotated before exposure.
- Development login and unrestricted private URL scanning are disabled.
- PostgreSQL uses TLS, backups, point-in-time recovery, and least-privilege credentials.
- `/healthz` is used for readiness; logs are shipped without request headers.
- Authorization endpoint rate limits and network policies are configured at ingress.
- Multiple replicas share PostgreSQL; rolling deployment starts only after migration compatibility is verified.
- The external Swagger UI assets are mirrored locally if internet-free operation is required.

## Key incident response

1. Revoke the exposed key in the console.
2. Issue a replacement and update the consumer through its secret manager.
3. Review `authorization_events` for the key ID and affected time window.
4. Investigate the exposure source; never restore a revoked key.
