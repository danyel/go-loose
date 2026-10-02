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

## Security and availability

- Use TLS for both Go Loose and the client application.
- Keep client secrets server-side and rotate them after suspected disclosure.
- Do not replace the middleware's fail-closed behavior with an allow-on-error fallback.
- Apply CSRF protection to state-changing routes in the client application; the package handles login `state`, not your application forms.
- The middleware checks Go Loose on every request for immediate revocation. Deploy Go Loose highly available and use a bounded HTTP timeout.
- API-key authentication and browser-user authentication are independent. Use `client.Middleware` for service/API keys and `BrowserAuth.Middleware` for logged-in users.

## Troubleshooting `403`

`403 your account does not have access to this application` means authentication succeeded but the user lacks an application grant. In Go Loose, open **Users**, select the user, choose **Manage**, and enable the target application. A missing or incorrect token header returns `401`, not `403`.
