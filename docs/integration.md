# Integrating a Go API

Install the module from its eventual repository location:

```bash
go get github.com/danyel/go-loose/client
```

Wrap a router or selected route group:

```go
package main

import (
	"log"
	"net/http"
	"time"

	goloose "github.com/danyel/go-loose/client"
)

func main() {
	access, err := goloose.New(goloose.Config{
		BaseURL:    "https://nmbs.goloose.local",
		Tenant:     "nmbs",
		Application: "guess",
		HTTPClient:  &http.Client{Timeout: 2 * time.Second},
	})
	if err != nil {
		log.Fatal(err)
	}

	protected := access.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := goloose.PrincipalFromContext(r.Context())
		w.Write([]byte("authorized by key " + principal.APIKeyName))
	}))

	mux := http.NewServeMux()
	mux.Handle("GET /api/guesses", protected)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	log.Fatal(http.ListenAndServe(":8090", mux))
}
```

Call the protected API:

```bash
curl -H 'X-API-Key: gl_REPLACE_WITH_ISSUED_SECRET' \
  https://nmbs.guess.local/api/guesses
```

The middleware sends the original method, URL path, and request host to Go Loose. It denies missing/invalid keys and control-plane errors, then removes `X-API-Key` before invoking the application handler. Read the authorized tenant/application/key identity with `PrincipalFromContext`.

## Importing the service contract

Expose an OpenAPI JSON or YAML route from the service, then use **Contracts → Import contract → Scan URL**. Private/internal URLs are blocked by default; production deployments that need internal discovery should use a restricted egress network and explicitly set `GO_LOOSE_ALLOW_PRIVATE_CONTRACT_URLS=true`.

Contracts can also be pasted into the console, which avoids server-side egress entirely.

## Availability and latency

The current client validates remotely on every request so revocation is immediate. Run Go Loose highly available and set a strict client timeout. Do not implement an “allow on error” fallback. A future signed-assertion mode can reduce latency while retaining bounded revocation delay.
