package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danyel/go-loose/internal/config"
)

func TestLoginGuardLocksAfterFiveFailures(t *testing.T) {
	guard := newLoginGuard()
	now := time.Now()
	for range 5 {
		if !guard.allowed("address|user@example.com", now) {
			t.Fatal("guard locked too early")
		}
		guard.fail("address|user@example.com", now)
	}
	if guard.allowed("address|user@example.com", now) {
		t.Fatal("guard did not lock after five failures")
	}
	guard.success("address|user@example.com")
	if !guard.allowed("address|user@example.com", now) {
		t.Fatal("successful login did not clear failures")
	}
}

func TestPasswordLoginIsRejectedOnSystemHost(t *testing.T) {
	server := &Server{
		cfg:        config.Config{AuthDomain: "auth.dev", LocalLogin: true},
		loginGuard: newLoginGuard(),
	}
	server.installed.Store(true)
	request := httptest.NewRequest(http.MethodPost, "http://auth.dev/auth/password", nil)
	response := httptest.NewRecorder()

	server.passwordLogin(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}
