package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danyel/go-loose/internal/config"
)

func TestRequireSameOriginAcceptsTenantHost(t *testing.T) {
	server := &Server{cfg: config.Config{BaseURL: "https://auth.dev"}}
	handler := server.requireSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "https://nmbs.auth.dev/api/v1/keys", nil)
	request.Header.Set("Origin", "https://nmbs.auth.dev")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestRequireSameOriginRejectsDifferentTenantHost(t *testing.T) {
	server := &Server{cfg: config.Config{BaseURL: "https://auth.dev"}}
	handler := server.requireSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler reached for cross-origin request")
	}))
	request := httptest.NewRequest(http.MethodPost, "https://nmbs.auth.dev/api/v1/keys", nil)
	request.Header.Set("Origin", "https://ypto.auth.dev")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

// TestRequireSameOriginSurvivesStaleBaseURL covers the deployment that made
// profile saves fail with "same-origin request required": the container was
// started with a base URL of "http://localhost:" while users browsed to
// https://auth.urpi.be. The configured base URL must not be the only accepted
// origin, or a stale value breaks every state-changing route at once.
func TestRequireSameOriginSurvivesStaleBaseURL(t *testing.T) {
	for _, baseURL := range []string{"http://localhost:", "", "http://localhost:8080", "not a url"} {
		server := &Server{cfg: config.Config{BaseURL: baseURL}}
		handler := server.requireSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		request := httptest.NewRequest(http.MethodPut, "https://auth.urpi.be/api/v1/profile", nil)
		request.Header.Set("Origin", "https://auth.urpi.be")
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusNoContent {
			t.Errorf("base URL %q: status = %d, want %d", baseURL, response.Code, http.StatusNoContent)
		}
	}
}

// TestRequireSameOriginAcceptsForwardedHTTPS covers a reverse proxy that
// terminates TLS: the server sees a plain HTTP connection, so the scheme has to
// come from X-Forwarded-Proto rather than from r.TLS.
func TestRequireSameOriginAcceptsForwardedHTTPS(t *testing.T) {
	server := &Server{cfg: config.Config{BaseURL: "http://go-loose:8080"}}
	handler := server.requireSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPut, "http://auth.urpi.be/api/v1/profile", nil)
	request.Host = "auth.urpi.be"
	request.Header.Set("Origin", "https://auth.urpi.be")
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestRequireSameOriginFallsBackToReferer(t *testing.T) {
	server := &Server{cfg: config.Config{BaseURL: "https://auth.dev"}}
	handler := server.requireSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "https://auth.dev/api/v1/tenants", nil)
	request.Header.Set("Referer", "https://auth.dev/console")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestRequireSameOriginRejectsMissingAndForeignSources(t *testing.T) {
	cases := []struct {
		name    string
		origin  string
		referer string
	}{
		{name: "no origin or referer"},
		{name: "foreign origin", origin: "https://evil.example"},
		{name: "null origin", origin: "null"},
		{name: "same host different scheme", origin: "http://auth.dev"},
		{name: "origin is a prefix of the host", origin: "https://auth.dev.evil.example"},
		{name: "referer from another tenant", referer: "https://ypto.auth.dev/profile"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := &Server{cfg: config.Config{BaseURL: "https://auth.dev"}}
			handler := server.requireSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Error("handler reached for a request that was not same-origin")
			}))
			request := httptest.NewRequest(http.MethodPost, "https://auth.dev/api/v1/tenants", nil)
			if testCase.origin != "" {
				request.Header.Set("Origin", testCase.origin)
			}
			if testCase.referer != "" {
				request.Header.Set("Referer", testCase.referer)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
			}
		})
	}
}
