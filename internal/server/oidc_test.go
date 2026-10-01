package server

import (
	"net/http/httptest"
	"testing"

	"github.com/danyel/go-loose/internal/config"
)

func TestOAuthStateCookieDomain(t *testing.T) {
	server := &Server{cfg: config.Config{AuthDomain: "auth.local"}}

	tenantRequest := httptest.NewRequest("GET", "http://nmbs.auth.local/auth/start", nil)
	if domain := server.oauthStateCookieDomain(tenantRequest); domain != "auth.local" {
		t.Fatalf("tenant cookie domain = %q, want auth.local", domain)
	}

	localRequest := httptest.NewRequest("GET", "http://localhost:8080/auth/start", nil)
	if domain := server.oauthStateCookieDomain(localRequest); domain != "" {
		t.Fatalf("local cookie domain = %q, want host-only cookie", domain)
	}
}
