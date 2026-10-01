package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddlewareAuthorizesAndAddsPrincipal(t *testing.T) {
	authorizationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(DefaultHeader) != "gl_test_key_that_is_long_enough_for_client" {
			t.Errorf("unexpected API key")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"allowed":true,"tenant_id":"tenant-1","tenant_slug":"nmbs","application_id":"app-1","application_slug":"guess","api_key_id":"key-1","api_key_name":"test"}`))
	}))
	defer authorizationServer.Close()

	client, err := New(Config{BaseURL: authorizationServer.URL, Tenant: "nmbs", Application: "guess"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	handler := client.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || principal.TenantSlug != "nmbs" {
			t.Fatalf("missing principal: %#v", principal)
		}
		if r.Header.Get(DefaultHeader) != "" {
			t.Fatal("middleware must not forward the credential")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://nmbs.guess.local/guesses", nil)
	request.Header.Set(DefaultHeader, "gl_test_key_that_is_long_enough_for_client")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestMiddlewareFailsClosedWithoutKey(t *testing.T) {
	client, err := New(Config{BaseURL: "http://go-loose", Application: "guess"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	called := false
	handler := client.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusUnauthorized || called {
		t.Fatalf("status = %d, called = %v", recorder.Code, called)
	}
}
