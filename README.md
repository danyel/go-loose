# Go Loose

Go Loose is a multi-tenant API-key control plane for Go HTTP services. It gives operators a web console to register tenant applications, issue and revoke keys, import OpenAPI contracts, and inspect API metadata. Applications use the public `client` package as fail-closed middleware: requests without a valid key never reach the protected handler.

## Start locally

```bash
docker compose up --build
```

Open <http://localhost:8080>. The Compose setup deliberately enables database login and private OpenAPI URL scanning for local development. Never use unrestricted private URL scanning in production.

On a fresh database, open <http://localhost:8080/install>, enter the Google OAuth client secret from Google Cloud Console, and optionally seed the NMBS and YPTO Guess demonstration data. The CMS Demo client ID and callback URL are prefilled. See the [installation guide](docs/installation.md) for Google setup, first-admin behavior, waiting-room approval, and all demo credentials.

Hosted user login for that tenant is served from `http://nmbs.auth.local:8080`; add `127.0.0.1 nmbs.auth.local` to `/etc/hosts` for local browser testing.

If port 8080 is occupied, run `GO_LOOSE_PORT=18080 docker compose up --build` and open <http://localhost:18080>.
If PostgreSQL port 5432 is occupied, also set `GO_LOOSE_POSTGRES_PORT=15432`.

The first Google SSO user becomes system administrator. Later SSO users remain in a waiting room until the system administrator assigns a tenant, role, and application access. Tenant administrators can manage only their own tenants.

## Request flow

```text
Caller
  └─ X-API-Key: gl_...
       └─ Your Go API + go-loose/client middleware
            └─ POST /api/v1/authorize → Go Loose
                 ├─ hash key, evaluate status/expiry/tenant/app/host
                 ├─ write authorization audit event
                 └─ allow with tenant/key principal OR deny
```

Only a SHA-256 digest and a short display prefix are stored. A plaintext key is shown once at creation. The client strips the credential before calling the protected handler.

## Configuration

Copy `.env.example` for direct local execution. Important settings:

| Variable | Purpose |
|---|---|
| `GO_LOOSE_DATABASE_URL` | PostgreSQL connection string |
| `GO_LOOSE_SESSION_SECRET` | At least 32 random characters; rotate through a planned session invalidation |
| `GO_LOOSE_BASE_URL` | Public origin, used for secure cookies and same-origin checks |
| `GO_LOOSE_OIDC_*` | OIDC issuer, client ID, secret, and callback URL |
| `GO_LOOSE_ALLOWED_EMAIL_DOMAINS` | Optional comma-separated SSO email-domain allowlist |
| `GO_LOOSE_LOCAL_LOGIN` | Enables database-backed login for seeded and invited users |
| `GO_LOOSE_LOCAL_ADMIN_PASSWORD` | Optional compatibility bootstrap; omit for installer-first deployment |
| `GO_LOOSE_DEV_LOGIN` | Local-only login; keep `false` in production |
| `GO_LOOSE_ALLOW_PRIVATE_CONTRACT_URLS` | Allows scanning internal/loopback OpenAPI URLs; local-only unless egress is isolated |

Production must place Go Loose behind TLS, use a secret manager, set `GO_LOOSE_BASE_URL` to the HTTPS origin, disable development login, and configure OIDC. Swagger UI is available at `/docs` only after login.

## Documentation

- [Architecture and decisions](docs/architecture.md)
- [First-run installation, waiting room, and demo accounts](docs/installation.md)
- [Go middleware integration](docs/integration.md)
- [Client application login](docs/client-login.md)
- [Database user authentication and local credentials](docs/password-authentication.md)
- [Operations, migrations, and OIDC](docs/operations.md)
- [Coding standards](docs/coding-standards.md)

## Development

```bash
go mod download
make fmt
make test
make vet
make build
```

Development requires Go 1.27.1 or newer.

Migrations run transactionally at startup and are tracked in `schema_migrations`. See the operations guide before creating one.
