package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danyel/go-loose/internal/config"
	"github.com/danyel/go-loose/internal/session"
)

func newInstallerTestServer() *Server {
	secret := strings.Repeat("s", 32)
	return &Server{
		cfg:      config.Config{BaseURL: "http://localhost:8080", SessionSecret: secret},
		sessions: session.New(secret, false),
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestFaviconDoesNotRedirectToInstaller(t *testing.T) {
	server := newInstallerTestServer()
	request := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("favicon status = %d, want 404; location %q", recorder.Code, recorder.Header().Get("Location"))
	}
	if recorder.Header().Get("Set-Cookie") != "" {
		t.Fatal("favicon response set a cookie")
	}
}

func TestUninstalledRootRedirectsToInstaller(t *testing.T) {
	server := newInstallerTestServer()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/install" {
		t.Fatalf("status %d location %q", recorder.Code, recorder.Header().Get("Location"))
	}
}

func TestInstallerCSRFTokenSurvivesRepeatedPageLoad(t *testing.T) {
	server := newInstallerTestServer()
	first := httptest.NewRecorder()
	server.Handler().ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/install", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first install page status = %d", first.Code)
	}
	cookie := first.Result().Cookies()[0]
	token := csrfTokenFromInstaller(t, first.Body.String())
	if cookie.Value != token {
		t.Fatalf("cookie %q does not match form token %q", cookie.Value, token)
	}

	secondRequest := httptest.NewRequest(http.MethodGet, "/install", nil)
	secondRequest.AddCookie(cookie)
	second := httptest.NewRecorder()
	server.Handler().ServeHTTP(second, secondRequest)
	if got := csrfTokenFromInstaller(t, second.Body.String()); got != token {
		t.Fatalf("second page rotated CSRF token to %q", got)
	}
	if second.Result().Cookies()[0].Value != token {
		t.Fatal("second response rotated CSRF cookie")
	}
}

func csrfTokenFromInstaller(t *testing.T, page string) string {
	t.Helper()
	const marker = `name="csrf_token" value="`
	start := strings.Index(page, marker)
	if start < 0 {
		t.Fatal("installer page has no csrf token")
	}
	start += len(marker)
	end := strings.Index(page[start:], `"`)
	if end < 0 {
		t.Fatal("installer csrf token is unterminated")
	}
	return page[start : start+end]
}
