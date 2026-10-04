# Coding standards

## Go

- Use the standard library unless a dependency clearly reduces security or protocol risk.
- Keep public APIs small, documented, and backward compatible.
- Pass `context.Context` through I/O boundaries and always bound network calls with timeouts.
- Wrap errors with the operation; never log secrets, cookies, authorization headers, or full API keys.
- Return explicit errors. Runtime authorization must fail closed.
- Keep SQL tenant-aware: management queries must join through membership, and writes must enforce role in the query or transaction.
- Derive authorization from the matrix in `internal/role` instead of hardcoding role names. Pass `role.Grants(...)` into SQL, use `role.Allows` in handlers, and render controls from the capability lists the server returns.
- Use cryptographically secure randomness for credentials and constant-time comparison for signatures.
- Format with `gofmt`; run `go test -race ./...`, `go vet ./...`, and `go build ./...`.

## HTTP API

- Routes are versioned under `/api/v1`; health and authentication routes are infrastructure exceptions.
- JSON handlers reject unknown fields, extra JSON values, and oversized bodies.
- Errors use `{"error":"human-readable message"}` without internal implementation details.
- Use `401` for absent/unusable authentication, `403` for authenticated credentials outside policy, `404` when existence must not disclose access, and `422` for semantically invalid contracts.
- Any management mutation requires a valid user session and same-origin browser request.
- Update `web/openapi.json` whenever endpoint behavior changes.

## Database

- Use UUID primary keys for tenant data and UTC `timestamptz` timestamps.
- Foreign keys declare deletion behavior; frequently queried authorization fields get explicit indexes.
- Applied migrations are immutable and forward-compatible.
- Multi-step writes use transactions. Do not add application-side checks that can race when a database constraint can enforce the invariant.

## Frontend

- Preserve keyboard access, semantic elements, visible focus, responsive layout, and sufficient contrast in every theme.
- Escape all server-provided strings before assigning HTML. Prefer `textContent` for new dynamic surfaces.
- Store only visual preferences in local storage; authentication remains in HTTP-only cookies.
- Keep the console dependency-free unless complexity justifies a reviewed build tool decision.

## Tests and reviews

- New domain behavior needs table-driven unit tests and negative cases.
- Security boundaries need explicit tests for missing, malformed, expired, cross-tenant, and unauthorized inputs.
- Integration tests that need PostgreSQL should use a disposable database and never shared developer data.
- Reviews prioritize tenant isolation, fail-closed behavior, migration compatibility, secret handling, and error visibility.

## Commit style

Use focused commits with imperative subjects, for example `Add scoped API key authorization`. Do not mix unrelated refactors with behavior changes. Explain migration and security implications in the commit body.
