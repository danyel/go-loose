package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danyel/go-loose/internal/config"
)

func TestOAuthStateCookieDomain(t *testing.T) {
	server := &Server{cfg: config.Config{AuthDomain: "auth.dev"}}

	tenantRequest := httptest.NewRequest("GET", "http://nmbs.auth.dev/auth/start", nil)
	if domain := server.oauthStateCookieDomain(tenantRequest); domain != "auth.dev" {
		t.Fatalf("tenant cookie domain = %q, want auth.dev", domain)
	}

	localRequest := httptest.NewRequest("GET", "http://localhost:8080/auth/start", nil)
	if domain := server.oauthStateCookieDomain(localRequest); domain != "" {
		t.Fatalf("local cookie domain = %q, want host-only cookie", domain)
	}
}

func TestManagementSSOIsRejectedOnTenantHost(t *testing.T) {
	server := &Server{cfg: config.Config{AuthDomain: "auth.dev"}}
	request := httptest.NewRequest(http.MethodGet, "http://nmbs.auth.dev/auth/start", nil)
	response := httptest.NewRecorder()

	server.authStart(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestClientSSOIsRejectedOnSystemHost(t *testing.T) {
	server := &Server{cfg: config.Config{AuthDomain: "auth.dev"}}
	request := httptest.NewRequest(http.MethodGet, "http://auth.dev/auth/start?return=client", nil)
	response := httptest.NewRecorder()

	server.authStart(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}
