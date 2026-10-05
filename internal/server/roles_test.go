package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/danyel/go-loose/internal/config"
	"github.com/danyel/go-loose/internal/session"
	"github.com/danyel/go-loose/web"
)

// withClaims injects a management session the way requireSession would, so a
// handler can be called directly without standing up a session manager.
func withClaims(request *http.Request, claims session.Claims) context.Context {
	return context.WithValue(request.Context(), claimsKey, claims)
}

func TestRolesPageIsEmbedded(t *testing.T) {
	content, err := web.Files.ReadFile("roles.html")
	if err != nil {
		t.Fatalf("roles.html must be embedded: %v", err)
	}
	for _, marker := range []string{
		"role-list", "role-form", "permission-list", "tenant-context", "/assets/roles.js",
	} {
		if !bytes.Contains(content, []byte(marker)) {
			t.Errorf("roles.html is missing %q", marker)
		}
	}
}

// TestRolesScriptIsServed guards the asset allowlist: roles.js is a new file, and
// the handler serves assets by exact name rather than by pattern.
func TestRolesScriptIsServed(t *testing.T) {
	server := profileTestServer()
	request := httptest.NewRequest(http.MethodGet, "https://auth.example.test/assets/roles.js", nil)
	request.SetPathValue("name", "roles.js")
	response := httptest.NewRecorder()

	server.asset(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), "/api/v1/roles") {
		t.Error("roles.js does not call the role endpoints")
	}
}

func TestAssetAllowlistRejectsUnknownFiles(t *testing.T) {
	server := profileTestServer()
	for _, name := range []string{"admin.js", "roles.html", "app.js.map", "secret.env"} {
		request := httptest.NewRequest(http.MethodGet, "https://auth.example.test/assets/"+name, nil)
		request.SetPathValue("name", name)
		response := httptest.NewRecorder()

		server.asset(response, request)

		if response.Code != http.StatusNotFound {
			t.Errorf("asset(%q) status = %d, want %d", name, response.Code, http.StatusNotFound)
		}
	}
}

// TestAssetTraversalCollapsesToTheAllowlistedName documents that a traversal
// attempt cannot escape the allowlist: path.Base reduces it to the bare file
// name, which is then matched against the list like any other request.
func TestAssetTraversalCollapsesToTheAllowlistedName(t *testing.T) {
	server := profileTestServer()
	for _, name := range []string{"../roles.js", "../../etc/passwd", "..%2froles.js"} {
		request := httptest.NewRequest(http.MethodGet, "https://auth.example.test/assets/"+name, nil)
		request.SetPathValue("name", name)
		response := httptest.NewRecorder()

		server.asset(response, request)

		served := path.Base(name)
		if served == "roles.js" {
			if response.Code != http.StatusOK {
				t.Errorf("asset(%q) status = %d, want the allowlisted file to serve", name, response.Code)
			}
			continue
		}
		if response.Code != http.StatusNotFound {
			t.Errorf("asset(%q) status = %d, want %d", name, response.Code, http.StatusNotFound)
		}
	}
}

func TestCreateRoleRejectsMalformedInputBeforeTouchingTheStore(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing slug", `{"name":"Role","permissions":[]}`},
		{"uppercase slug", `{"slug":"Release Manager","name":"Role","permissions":[]}`},
		{"slug starting with a dash", `{"slug":"-role","name":"Role","permissions":[]}`},
		{"empty name", `{"slug":"role","name":"   ","permissions":[]}`},
	}
	// Permission names are not checked here: the catalog is a table, so an unknown
	// name can only be caught by the store, which reports it as a bad request.
	// See TestARoleCannotGrantAPermissionThatIsNotInTheCatalog.
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := profileTestServer()
			request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/api/v1/roles",
				strings.NewReader(testCase.body))
			request.SetPathValue("id", "")
			request = request.WithContext(withClaims(request, session.Claims{UserID: "user-1", Management: true}))
			response := httptest.NewRecorder()

			server.createRole(response, request)

			// The store would need a database, so a 400 proves validation ran first.
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (body %s)", response.Code, http.StatusBadRequest, response.Body)
			}
		})
	}
}

func TestListRolesRequiresATenant(t *testing.T) {
	server := profileTestServer()
	request := httptest.NewRequest(http.MethodGet, "https://auth.example.test/api/v1/roles", nil)
	request = request.WithContext(withClaims(request, session.Claims{UserID: "user-1", Management: true}))
	response := httptest.NewRecorder()

	server.listRoles(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if !strings.Contains(response.Body.String(), "tenant_id") {
		t.Errorf("body = %s, want it to name the missing parameter", response.Body)
	}
}

// TestRoleRoutesAreRegistered documents the two wrappers the role routes rely
// on. The server under test is not installed, so requireSession redirects every
// session-guarded route to the installer; an unregistered route would answer 404
// instead, which is what makes this a registration check.
func TestRoleRoutesAreRegistered(t *testing.T) {
	// Handler() wraps every route in the request logger, so this server needs a
	// logger where the profile tests, which call handlers directly, do not.
	server := &Server{
		cfg:    config.Config{BaseURL: "https://auth.example.test"},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler := server.Handler()
	cases := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/roles?tenant_id=t"},
		{http.MethodPost, "/api/v1/roles"},
		{http.MethodPut, "/api/v1/roles/abc"},
		{http.MethodDelete, "/api/v1/roles/abc"},
		{http.MethodGet, "/roles"},
	}
	for _, testCase := range cases {
		t.Run(testCase.method+" "+testCase.path, func(t *testing.T) {
			request := httptest.NewRequest(testCase.method, "https://auth.example.test"+testCase.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want %d from requireSession", response.Code, http.StatusSeeOther)
			}
			if location := response.Header().Get("Location"); location != "/install" {
				t.Fatalf("location = %q, want /install", location)
			}
		})
	}
}
