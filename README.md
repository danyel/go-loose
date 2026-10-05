# Go Loose

Go Loose is a multi-tenant API-key control plane for Go HTTP services. It gives operators a web console to register tenant applications, issue and revoke keys, import OpenAPI contracts, and inspect API metadata. Applications use the public `client` package as fail-closed middleware: requests without a valid key never reach the protected handler.

## Start locally

```bash
docker compose up --build
```

Start the shared TLS proxy using `/home/dnoulet/go/infrasctruture`, add
`127.0.0.1 auth.dev nmbs.auth.dev ypto.auth.dev` to `/etc/hosts`, then open
<https://auth.dev>. The Compose setup deliberately enables database login and
private OpenAPI URL scanning for local development. Never use unrestricted
private URL scanning in production.

On a fresh database, open <https://auth.dev/install>, enter the Google OAuth client secret from Google Cloud Console, and optionally seed the NMBS and YPTO Guess demonstration data. The CMS Demo client ID and callback URL are prefilled. See the [installation guide](docs/installation.md) for Google setup, first-admin behavior, waiting-room approval, and all demo credentials.

The bare `auth.dev` host is reserved for system-administrator SSO. Tenant administrators use database credentials on their tenant host, such as `https://nmbs.auth.dev`.

If PostgreSQL port 5433 is occupied, set `GO_LOOSE_POSTGRES_PORT=15432`.

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
- [Tenant roles, capabilities, and profile pictures](docs/roles.md)
- [Database user authentication and local credentials](docs/password-authentication.md)
- [Operations, migrations, and OIDC](docs/operations.md)
- [Coding standards](docs/coding-standards.md)

## Profile

Every management session can open `/profile` to set a display name and a profile picture. Pictures are stored in PostgreSQL and served from a public, unguessable URL that client applications can embed directly. Display names stop being overwritten by the identity provider once the user customizes them. See [roles and capabilities](docs/roles.md).

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

`make integration-db` creates the two scratch databases the database-backed tests use, and `make integration-test` runs them. Those tests drop every table they touch, so they refuse to run against a database whose name does not contain `test`. That guard exists because pointing them at a development database destroys it.

### Hot reload

`make compose-dev-up` starts a development stack that runs Go Loose under [Air](https://air-verse.github.io/). Air watches `cmd`, `internal`, `client`, and `web`, rebuilds on every change, and writes the binary to `./dist`. Changes to `web/` are embedded at build time, so editing a template, stylesheet, or script triggers a rebuild too. The server restarts in place and `/healthz` confirms it came back.

```bash
make compose-dev-up      # build the image, start postgres and Air
make compose-dev-logs    # follow the rebuild and request logs
make compose-dev-down    # stop and remove the stack
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `GO_LOOSE_DEV_PORT` | `8080` | Host port for the dev server |
| `GO_LOOSE_POSTGRES_PORT` | `5433` | Host port for PostgreSQL |

The dev stack binds mounts the source tree, so Air writes `dist/go-loose` as `root` inside the container. On Linux, delete it with `sudo rm dist/go-loose` if the file ownership gets in the way.

`docker-compose.yaml` remains the stack that matches production: a distroless image, no dev login, and the `local-dev-edge` network. `docker-compose.dev.yaml` and `Dockerfile.dev` are development-only.

The database is not bind mounted into the source tree: PostgreSQL stores its files as `0700` owned by its own user, which would make `go build ./...` fail to walk the directory. `docker-compose.yaml` uses the `db-data` volume and `docker-compose.dev.yaml` uses a separate `db-data-dev`, so `docker compose -f docker-compose.dev.yaml down -v` cannot reach the real database. Reach a database through the published `5433` port or `docker compose exec postgres psql -U goloose -d goloose`.

The dev database starts empty and migrations rebuild it on boot. `make compose-dev-down` also empties `./dist`, because Air writes that binary as `root` inside the container.

