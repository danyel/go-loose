# First-run installation and demo data

## Clean installation

Start Go Loose with PostgreSQL and a stable `GO_LOOSE_SESSION_SECRET` of at least 32 characters. No OIDC environment variables or bootstrap account are required:

```bash
docker compose up --build
```

Open `http://localhost:8080/install`. The installer asks for a Google OAuth client ID and client secret. In Google Cloud Console, configure this authorized redirect URI before submitting:

```text
http://localhost:8080/auth/callback
```

The supplied **CMS Demo** client ID is prefilled:

```text
554628171917-forvpfs44pqajv77dfhl503prfqnhor3.apps.googleusercontent.com
```

The Google client secret is not included in the repository and must be copied from Google Cloud Console. Go Loose validates Google OIDC discovery, encrypts the secret with AES-GCM using a key derived from `GO_LOOSE_SESSION_SECRET`, and stores only the ciphertext in PostgreSQL. Keep the session secret stable: losing it makes the installed OIDC secret undecryptable.

Installation is a one-time operation. Submitting the installer immediately starts Google login. Google redirects to `/auth/callback`, where Go Loose validates the ID token, creates a signed HTTP-only session cookie, and redirects to the management console. Browser redirects cannot carry a caller-defined `Authorization` header, so no bearer token is exposed in the URL or to frontend JavaScript.

Later requests to `/install` redirect to login, and duplicate submissions are rejected.

## First administrator and waiting room

The first user who completes Google SSO becomes the system administrator. A PostgreSQL advisory transaction lock makes this first-user claim atomic when multiple users sign in concurrently. The system administrator receives owner access to every tenant and application that exists at that moment.

Later first-time SSO users are created without tenant membership. Their management page shows only the waiting room. A system administrator approves a waiting user from **Users & access**, selecting:

- the tenant;
- tenant role (`viewer`, `admin`, or `owner`);
- the applications the user may log in to.

Tenant owners and administrators can manage users, applications, API keys, client login, and OpenAPI contracts only inside their assigned tenants. A user assigned to multiple tenants can switch the active tenant from the console header. Database membership checks—not the selector—enforce isolation.

## Optional Guess demonstration seed

The installer selects the demonstration seed by default. It creates the `nmbs` and `ypto` tenants, one `guess` application in each tenant, and these local database users:

| Tenant | Email | Password | Role |
|---|---|---|---|
| NMBS | `interview@nmbs.auth.local` | `admin123` | Tenant administrator |
| YPTO | `interview@ypto.auth.local` | `admin123` | Tenant administrator |
| NMBS | `reviewer@nmbs.auth.local` | `Demo-Nmbs-2026!` | Tenant administrator |
| YPTO | `reviewer@ypto.auth.local` | `Demo-Ypto-2026!` | Tenant administrator |

All four users receive access only to their tenant's Guess application. Passwords are stored as Argon2id hashes; plaintext credentials are never written to PostgreSQL.

These accounts and especially `admin123` are intentionally non-production credentials. Disable the seed for production, or delete/rotate every demo account before exposing the service.

For local hosted-login testing, add:

```text
127.0.0.1 nmbs.auth.local ypto.auth.local
```

The tenant login origins are then:

```text
http://nmbs.auth.local:8080
http://ypto.auth.local:8080
```

An application must first have exact redirect URIs and a generated client secret configured in the management console before `/connect/authorize` can start its login flow.

## Environment-configured compatibility mode

Existing deployments may continue to supply all three `GO_LOOSE_OIDC_ISSUER`, `GO_LOOSE_OIDC_CLIENT_ID`, and `GO_LOOSE_OIDC_CLIENT_SECRET` variables. Go Loose treats that as an already configured deployment and bypasses the installer. Supplying `GO_LOOSE_LOCAL_LOGIN=true` together with a non-empty `GO_LOOSE_LOCAL_ADMIN_PASSWORD` does the same for a database-only development deployment.

For new installations, prefer the web installer. `GO_LOOSE_LOCAL_LOGIN=true` without a bootstrap password enables seeded and invited database users but does not bypass installation.
