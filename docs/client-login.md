# Client application login

Go Loose can host login for browser-facing Go applications. Your application never handles the user's IdP password. It redirects the browser to Go Loose, receives a short-lived one-time authorization code, exchanges that code from its backend using a client secret, and stores the returned opaque session in an HTTP-only cookie.

## 1. Configure the application in Go Loose

1. Open **Applications** and choose **Configure client login**.
2. Add the exact callback URL, for example `https://nmbs.guess.local/auth/callback`.
3. Save and copy the client secret. It is shown once.
4. Open **Users**, invite the user by the email returned by the IdP, and choose **Manage** to grant access to the application.

The invitation requires an initial password. Tenant login hosts accept database credentials only; SSO is reserved for system administration on the bare authentication domain.

Saving client configuration rotates the secret. Callback URLs require HTTPS, except `localhost` and `127.0.0.1` while Go Loose development login is enabled.

## 2. Add the Go client

```bash
go get github.com/danyel/go-loose/client
```

Configure the hosted login and register its handlers:

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	goloose "github.com/danyel/go-loose/client"
)

func main() {
	auth, err := goloose.NewBrowserAuth(goloose.BrowserAuthConfig{
		BaseURL:        "https://nmbs.auth.example.com",
		ClientID:       os.Getenv("GO_LOOSE_CLIENT_ID"),
		ClientSecret:   os.Getenv("GO_LOOSE_CLIENT_SECRET"),
		RedirectURL:    "https://nmbs.guess.local/auth/callback",
		AfterLoginURL:  "/app",
		AfterLogoutURL: "/",
		LoginPath:      "/login",
		CookieSecure:   true,
		HTTPClient:     &http.Client{Timeout: 3 * time.Second},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", auth.LoginHandler)
	mux.HandleFunc("GET /auth/callback", auth.CallbackHandler)
	mux.HandleFunc("POST /logout", auth.LogoutHandler)

	protected := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := goloose.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "user missing", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Hello %s from tenant %s", user.DisplayName, user.TenantSlug)
	}))
	mux.Handle("GET /app", protected)
	mux.Handle("GET /api/profile", protected)

	log.Fatal(http.ListenAndServe(":8090", mux))
}
```

Keep `GO_LOOSE_CLIENT_SECRET` in a secret manager, never source control. In local development, configure an exact callback such as `http://localhost:8090/auth/callback` and set `CookieSecure: false`.

## Tenant login hostname

Each tenant has its own login origin:

```text
https://<tenant-slug>.<GO_LOOSE_AUTH_DOMAIN>
```

For tenant `nmbs` with `GO_LOOSE_AUTH_DOMAIN=auth.dev`, configure the Go client with:

```go
BaseURL: "http://nmbs.auth.dev:18080"
```

For local development, add the tenant hostname to `/etc/hosts`:

```text
127.0.0.1 nmbs.auth.dev
```

Production should configure wildcard DNS and TLS for `*.auth.example.com`, route those hosts to Go Loose, and use:

```dotenv
GO_LOOSE_BASE_URL=https://auth.example.com
GO_LOOSE_AUTH_DOMAIN=auth.example.com
GO_LOOSE_OIDC_REDIRECT_URL=https://auth.example.com/auth/callback
```

The client package initially redirects to `/connect/authorize`. Go Loose verifies the registered client and exact callback, canonicalizes the browser onto the tenant hostname, and renders `<Tenant name> login` for the requested application.

## 3. Browser flow

```text
Browser → GET /login on client application
        → GET /connect/authorize on Go Loose
        → separate Go Loose client login
        → organization OIDC provider
        → Go Loose validates user + application grant
        → client /auth/callback?code=...&state=...
Client  → POST /connect/token with Authorization: Basic <client-id:secret>
        ← opaque 12-hour session token
Browser ← HTTP-only SameSite session cookie on client application
Request → client middleware → GET /connect/userinfo → protected handler
                                      Authorization: Bearer <opaque-session>
```

The authorization code expires after two minutes and can be used once. Redirect URIs must match exactly. Removing a user's application grant immediately makes `/connect/userinfo` reject existing sessions. Logout revokes the central session and clears the local cookie.

## Role and profile picture

Both `/connect/token` and `/connect/userinfo` return the caller's `role`, `permissions`, and absolute `avatar_url`, resolved against the tenant that owns the application:

```json
{
  "id": "9f0f...",
  "email": "ada@example.com",
  "display_name": "Ada Lovelace",
  "avatar_url": "https://loose.example.com/api/v1/avatars/kZ3...",
  "tenant_id": "2b41...",
  "tenant_slug": "nmbs",
  "application_id": "7c02...",
  "application": "guess",
  "role": "developer",
  "permissions": [
    "console.read",
    "users.read",
    "applications.manage",
    "keys.manage",
    "contracts.manage",
    "users.manage",
    "profile.edit"
  ]
}
```

There is no `can` object on the wire. `avatar_url` is public by design, so it can be embedded directly with a plain image tag; it is an empty string when the user has not uploaded a picture.

Read `permissions` rather than testing `role` by name, because a tenant may define its own roles. The client package exposes the same check as a method:

```go
if user.Can("contracts.manage") {
	// the role behind this session grants it
}
```

A user with no membership in the application's tenant still authenticates, but falls back to the built-in `user` role, whose only permission is `profile.edit`. See [roles, permissions, and profiles](roles.md).

## Security and availability

- Use TLS for both Go Loose and the client application.
- Keep client secrets server-side and rotate them after suspected disclosure.
- Do not replace the middleware's fail-closed behavior with an allow-on-error fallback.
- Apply CSRF protection to state-changing routes in the client application; the package handles login `state`, not your application forms.
- The middleware checks Go Loose on every request for immediate revocation. Deploy Go Loose highly available and use a bounded HTTP timeout.
- Signing out in Go Loose revokes every hosted-login session the user holds here, so
  the client applications stop accepting their tokens on the next request. See
  [Signing out across the family](#signing-out-across-the-family).
- API-key authentication and browser-user authentication are independent. Use `client.Middleware` for service/API keys and `BrowserAuth.Middleware` for logged-in users.
- **A `user_application_access` grant is the only thing that admits a person to your
  application.** The system administrator is not an exception: they own every tenant,
  which is what lets them administer it, but ownership does not sign them in here.
  Nobody, administrator included, reaches your application without a grant recorded
  against your `client_id`. If support needs to see the application as a user, grant
  it deliberately from **Users & access** so it is attributable and revocable, rather
  than assuming the administrator is already inside.

## Signing out across the family

Applications in this family share one identity, so signing out has to mean more than
clearing one cookie. `POST /auth/logout` does three things, in this order:

1. **Revokes every hosted-login session the user holds.** Go Loose issues the bearer
   tokens these applications authenticate with, so this is what actually signs them
   out: their tokens stop resolving immediately, without the application being told
   or having to ask. This step reads the session first, which is why it happens before
   the cookie is cleared.
2. **Clears the local management cookies** on the identity domain.
3. **Sends the browser to the identity provider's logout endpoint**, when the provider
   advertises one in its discovery document, so the single sign-on session ends too.

Two consequences worth designing around:

- **A client application is signed out on its next request, not by being notified.**
  Its own session cookie still exists; the bearer token inside it has been revoked. An
  application that only checks the session locally will appear signed in until its
  next call to Go Loose, at which point it should treat the rejection as a sign-out and
  return the browser to `/login`.
- **Applications that authenticate against a different provider are not covered.**
  The provider endpoint is read from the issuer Go Loose itself is configured with, so
  this covers the applications that sign in through Go Loose. One pointed at a separate
  identity provider needs its own end-session redirect.

A provider that does not advertise `end_session_endpoint` is not an error: step 3 is
skipped and the user lands back on the sign-in page, having still been signed out
locally and revoked. Go Loose sends `client_id` and `post_logout_redirect_uri` rather
than an `id_token_hint`, because a hint would mean keeping a live credential in the
browser cookie between login and logout.

## Applications on the local platform

The local platform signs in two client applications, both with the wildcard
identity domain `auth.dev`:

| Application | Tenant | Callback URL |
|---|---|---|
| Go Guess | `nmbs` | `https://nmbs.guess.dev/api/auth/callback` |
| Go Guess | `ypto` | `https://ypto.guess.dev/api/auth/callback` |
| Go Tell | `tell` | `https://tell.dev/api/auth/callback` |

Go Guess has one application per tenant because it serves one host per tenant.
Go Tell has a single application: it is served from one host with no tenant
routing, so one client covers every request.

Client secrets are shown once when an application is configured. The Compose
stack reads them from a gitignored `.env`, and the Kubernetes releases receive
them through their release secret. Go Loose hashes stored secrets, so a lost
secret can only be replaced, never recovered.

Cluster clients cannot reach the workstation Traefik that serves `auth.dev`.
Both releases therefore mount the platform CA and expect a reachable identity
address, and a `502` on `/api/auth/callback` means the pod cannot reach Go
Loose rather than that the client is misconfigured.

## Troubleshooting `403`

`403 your account does not have access to this application` means authentication succeeded but the user lacks an application grant. In Go Loose, open **Users**, select the user, choose **Manage**, and enable the target application. A missing or incorrect token header returns `401`, not `403`.
