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
