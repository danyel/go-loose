# Database user authentication

Go Loose supports local email/password accounts stored in PostgreSQL. Passwords are never stored in plaintext: the server uses Argon2id with a random 16-byte salt, 64 MiB of memory, three iterations, and two lanes.

## Seeded Docker credentials

On a fresh Compose deployment, use `/install` and keep **Seed NMBS and YPTO Guess demo data** selected. The complete credential table is in the [installation guide](installation.md). The two primary interview accounts are:

```text
interview@nmbs.auth.local / admin123
interview@ypto.auth.local / admin123
```

For tenant application login, add `127.0.0.1 nmbs.auth.local ypto.auth.local` to `/etc/hosts`.

```text
http://nmbs.auth.local:8080
```

If alternate ports are needed:

```bash
GO_LOOSE_PORT=18080 \
GO_LOOSE_POSTGRES_PORT=15432 \
docker compose up --build
```

Then use `http://localhost:18080/login` and `http://nmbs.auth.local:18080`.

## Configuration

```dotenv
GO_LOOSE_LOCAL_LOGIN=true
GO_LOOSE_LOCAL_ADMIN_EMAIL=admin@example.com              # optional bootstrap
GO_LOOSE_LOCAL_ADMIN_PASSWORD=<at-least-12-characters>    # optional bootstrap
```

`GO_LOOSE_LOCAL_LOGIN=true` enables all database-backed users. A bootstrap account is created only when `GO_LOOSE_LOCAL_ADMIN_PASSWORD` is non-empty; its password is applied only when the account has no password hash. Changing the environment variable later does not silently overwrite an existing database password. If a bootstrap account is required, inject its password from a secret manager and never document a production credential.

## Creating client users

1. Sign in to the management console.
2. Open **Users** and choose **Invite user**.
3. Enter the user's email, display name, initial password, and tenant role.
4. Choose **Manage** for that user and grant the required applications.
5. Give the initial credential to the user through a secure channel.

The user can then sign in on `<tenant>.auth.local` or the production tenant auth hostname. Re-inviting an existing email explicitly replaces its password and display name.

## Brute-force and audit behavior

- Five failed attempts for the same IP/email pair within ten minutes cause a fifteen-minute lock.
- Invalid emails and invalid passwords return the same response.
- Unknown-user attempts still run Argon2id verification to reduce timing differences.
- Successful, failed, and rate-limited attempts are written to `user_login_events`.
- Authentication sessions remain signed HTTP-only cookies. Tenant client-login sessions cannot access the management console.
