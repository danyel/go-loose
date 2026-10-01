# Architecture and decisions

## Scope

Go Loose is an authorization control plane, not an API gateway. Protected applications keep serving their own traffic and use the client middleware to ask Go Loose whether an incoming key is authorized. This minimizes coupling and lets a service adopt Go Loose one route group at a time.

## Components

```text
cmd/go-loose
  configuration → migrations → HTTP server

internal/server
  OIDC/session auth, management API, authorization endpoint, embedded web UI

internal/store
  tenant-isolated PostgreSQL queries and authorization audit writes

internal/key
  cryptographically random key generation and one-way lookup hashing

internal/contract
  OpenAPI 2/3 JSON/YAML normalization and endpoint extraction

client
  public net/http middleware package used by other Go modules
```

PostgreSQL is the source of truth. The frontend is dependency-free HTML/CSS/JavaScript embedded in the Go binary. This creates one immutable artifact and avoids a second package ecosystem while the product is young.

## Tenant model

- A **tenant** is an organization such as `nmbs`.
- An **application** is a protected API such as `guess` and always belongs to one tenant.
- An **API key** belongs to exactly one application and tenant.
- A **membership** grants a user `owner`, `admin`, or `viewer` access to a tenant.
- An **application access grant** allows a user to sign in to one client application.
- `allowed_hosts` optionally binds keys for an application to hosts such as `nmbs.guess.local`.
- Tenant and application slugs are sent by middleware, so identical application names can safely exist in different tenants.

Hostnames are authorization context, not tenant identity. Do not trust a host alone: the key, expected tenant, expected application, and optional allowed host must all agree.

## Security decisions

1. **Fail closed.** Missing keys, Go Loose outages, malformed responses, inactive keys, expired keys, scope mismatches, and host mismatches deny the request.
2. **No plaintext key persistence.** Keys contain 256 random bits and are stored as SHA-256 digests. High-entropy secrets do not require a slow password hash for offline resistance.
3. **Session isolation.** Management uses signed, HTTP-only, SameSite cookies. Mutations additionally require the configured same origin.
4. **OIDC validation.** The server uses provider discovery and validates issuer, audience, signature, and expiry through `go-oidc`.
5. **SSRF resistance.** Contract import allows only HTTP(S), resolves hostnames, and blocks loopback/private/link-local destinations unless explicitly enabled.
6. **Auditing.** Every runtime decision records tenant, application, key, route context, outcome, and reason. Raw keys are never logged.
7. **Least privilege.** Management writes require tenant `owner` or `admin`. Read access requires membership.
8. **Separate login purpose.** Client login sessions cannot open the management console. Hosted login uses exact callback matching, one-time codes, confidential client secrets, and opaque revocable sessions.

For production, add rate limiting at the ingress, PostgreSQL backups, metrics/tracing, audit retention, membership invitations, key rotation overlap, and a tightly controlled egress proxy for contract scanning.

## OpenAPI contracts

Imported OpenAPI 2.x/3.x documents are normalized to JSON and stored unchanged in meaning. Methods, paths, and operation IDs are extracted into relational rows for discovery. Contracts are currently informational: they do not restrict runtime paths. Enforcing contract endpoints later should be opt-in per application to avoid breaking existing consumers.

## Decision log

| Decision | Choice | Reason |
|---|---|---|
| Deployment | One Go binary | Simple operations and atomic frontend/backend releases |
| Database | PostgreSQL | Strong tenant relations, transactions, JSONB contracts, and mature operations |
| Router | Go `http.ServeMux` | Modern method/path routing without another framework |
| UI | Embedded vanilla web assets | Fast startup, small supply chain, no Node runtime/build |
| Identity | OIDC Authorization Code flow | Works with Keycloak, Entra ID, Auth0, Okta, and other compliant IdPs |
| API keys | Random opaque secret + SHA-256 digest | Efficient indexed validation without recoverable secrets |
| Migrations | Embedded ordered SQL | Reviewable schema history and automatic transactional upgrades |
| Runtime integration | Remote authorization middleware | Immediate revocation and centralized audit; availability must be engineered |

## Planned evolution

1. Membership invitations and IdP group-to-role mapping.
2. Key rotation pairs and usage analytics.
3. Optional short-lived signed authorization assertions to reduce control-plane latency.
4. Per-application contract enforcement and route-level scopes.
5. Webhooks and audit export.
6. High-availability deployment, telemetry, and policy-based rate limits.
