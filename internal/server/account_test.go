package server

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/danyel/go-loose/internal/config"
	"github.com/danyel/go-loose/internal/database"
	"github.com/danyel/go-loose/internal/session"
	"github.com/danyel/go-loose/internal/store"
	"github.com/danyel/go-loose/web"
)

// logoutServer builds a server with a session manager so logout can be exercised
// end to end. The store is nil, so the client-session revocation is expected to
// panic-free no-op only where it is guarded; these tests therefore exercise the
// redirect behaviour, which is what a person sees.
func logoutServer(t *testing.T) *Server {
	t.Helper()
	secret := strings.Repeat("s", 32)
	return &Server{
		cfg:      config.Config{BaseURL: "https://auth.example.test", AuthDomain: "auth.example.test"},
		sessions: session.New(secret, false),
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// TestLogoutClearsTheSessionAndReturnsToSignIn is the baseline: with no identity
// provider logout endpoint configured, signing out lands back on the sign-in page.
func TestLogoutClearsTheSessionAndReturnsToSignIn(t *testing.T) {
	server := logoutServer(t)
	response := httptest.NewRecorder()
	server.authLogout(response, httptest.NewRequest(http.MethodPost, "https://auth.example.test/auth/logout", nil))

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if location := response.Header().Get("Location"); location != "/login" {
		t.Fatalf("location = %q, want /login", location)
	}
	var cleared bool
	for _, cookie := range response.Result().Cookies() {
		if cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not clear the session cookie")
	}
}

// TestLogoutEndsTheProviderSessionWhenAdvertised covers the cross-application half:
// when the provider publishes an end_session_endpoint the browser is sent there, so
// the single sign-on session the other applications share is ended too.
func TestLogoutEndsTheProviderSessionWhenAdvertised(t *testing.T) {
	server := logoutServer(t)
	server.endSession = "https://idp.example.test/protocol/openid-connect/logout"
	server.oauth = &oauth2ConfigStub

	response := httptest.NewRecorder()
	server.authLogout(response, httptest.NewRequest(http.MethodPost, "https://auth.example.test/auth/logout", nil))

	location := response.Header().Get("Location")
	if !strings.HasPrefix(location, server.endSession) {
		t.Fatalf("location = %q, want the provider logout endpoint", location)
	}
	for _, want := range []string{
		"client_id=go-loose",
		"post_logout_redirect_uri=https%3A%2F%2Fauth.example.test%2Flogin",
	} {
		if !strings.Contains(location, want) {
			t.Errorf("location = %q, want it to contain %q", location, want)
		}
	}
}

// TestLogoutSkipsTheProviderWhenItIsUnconfigured documents the fallback: a
// deployment whose provider does not advertise a logout endpoint still signs the
// user out locally rather than erroring.
func TestLogoutSkipsTheProviderWhenItIsUnconfigured(t *testing.T) {
	for name, configure := range map[string]func(*Server){
		"no endpoint":    func(s *Server) {},
		"no client id":   func(s *Server) { s.endSession = "https://idp.example.test/logout" },
		"unparseable":    func(s *Server) { s.endSession = "://nope"; s.oauth = &oauth2ConfigStub },
		"nothing set up": func(s *Server) { s.endSession = "" },
	} {
		t.Run(name, func(t *testing.T) {
			server := logoutServer(t)
			configure(server)
			response := httptest.NewRecorder()
			server.authLogout(response, httptest.NewRequest(http.MethodPost, "https://auth.example.test/auth/logout", nil))

			if location := response.Header().Get("Location"); location != "/login" {
				t.Fatalf("location = %q, want the local fallback /login", location)
			}
		})
	}
}

// TestAccountMenuIsEmbedded guards the component: it is mounted by every page, so a
// page that forgets the placeholder loses the whole control.
func TestAccountMenuIsEmbedded(t *testing.T) {
	for _, page := range []string{"index.html", "profile.html", "roles.html"} {
		t.Run(page, func(t *testing.T) {
			content, err := web.Files.ReadFile(page)
			if err != nil {
				t.Fatalf("%s must be embedded: %v", page, err)
			}
			text := string(content)
			for _, marker := range []string{"data-account-menu", "/assets/account.js"} {
				if !strings.Contains(text, marker) {
					t.Errorf("%s is missing %q", page, marker)
				}
			}
			// The account control replaces the separate sign-out button, so the
			// page must not still carry one or the header shows two of each.
			if strings.Contains(text, `<form action="/auth/logout"`) {
				t.Errorf("%s still renders its own logout form", page)
			}
			if strings.Contains(text, `id="identity"`) {
				t.Errorf("%s still renders the old identity chip", page)
			}
		})
	}
}

func TestAccountMenuScriptIsServed(t *testing.T) {
	server := &Server{cfg: config.Config{BaseURL: "https://auth.example.test"}}
	request := httptest.NewRequest(http.MethodGet, "https://auth.example.test/assets/account.js", nil)
	request.SetPathValue("name", "account.js")
	response := httptest.NewRecorder()

	server.asset(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	// The sign-out item has to be a form post, not a fetch, so that signing out
	// still works with scripting unavailable.
	if !strings.Contains(body, `method="post"`) || !strings.Contains(body, "/auth/logout") {
		t.Error("the account menu must post to /auth/logout to sign out")
	}
}

// TestRowActionsDoNotUseCardStyling pins the table fix. .card-action is
// width:100% with a 16px top margin for the foot of a card, which made two buttons
// stacked in a narrow cell taller than the rest of the row.
func TestRowActionsDoNotUseCardStyling(t *testing.T) {
	for _, page := range []string{"app.js", "roles.js"} {
		content, err := web.Files.ReadFile(page)
		if err != nil {
			t.Fatalf("%s must be embedded: %v", page, err)
		}
		if strings.Contains(string(content), "table-actions") == false {
			t.Errorf("%s does not use the table action wrapper", page)
		}
	}
	css, err := web.Files.ReadFile("style.css")
	if err != nil {
		t.Fatalf("style.css must be embedded: %v", err)
	}
	if !strings.Contains(string(css), ".table-action{") {
		t.Error("style.css has no .table-action rule, so row buttons would be unstyled")
	}
}

// oauth2ConfigStub carries the client id logout needs without reaching a provider.
var oauth2ConfigStub = oauth2.Config{ClientID: "go-loose"}

// TestLogoutRevokesHostedLoginSessions is the test that matters for cross-application
// sign-out. Go Loose issues the bearer tokens the tenant applications authenticate
// with, so revoking them here is what makes those applications reject the user
// without ever being told. Both halves need real rows: a real session cookie and a
// real client session.
func TestLogoutRevokesHostedLoginSessions(t *testing.T) {
	ctx := t.Context()

	// The store is opened over PostgreSQL, which is what this project uses; there is
	// no in-memory engine to substitute. The test skips when none is reachable rather
	// than failing, so the rest of the suite still runs without a database.
	db, err := database.Open(ctx, testDatabaseURL(t))
	if err != nil {
		t.Skipf("no test database available: %v", err)
	}
	defer db.Close()
	if err := resetSchema(ctx, db); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st := store.New(db)

	// A tenant with an application the owner can sign in to, and a live hosted-login
	// session issued from it.
	owner, err := st.UpsertUser(ctx, "local:owner@example.test", "owner@example.test", "Owner")
	if err != nil {
		t.Fatalf("upsert owner: %v", err)
	}
	tenant, err := st.CreateTenant(ctx, owner.ID, "acme", "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	app, err := st.CreateApplication(ctx, owner.ID, store.Application{
		TenantID: tenant.ID, Slug: "client", Name: "Client", AllowedHosts: []string{},
	})
	if err != nil {
		t.Fatalf("create application: %v", err)
	}
	secretHash := []byte("hashed-client-secret")
	if _, err := st.ConfigureClient(ctx, owner.ID, app.ID, []string{"https://app.example.test/cb"}, secretHash); err != nil {
		t.Fatalf("configure client: %v", err)
	}
	ownerRole, err := st.SystemRoleID(ctx, "owner")
	if err != nil {
		t.Fatalf("owner role: %v", err)
	}
	if err := st.SetUserAccess(ctx, owner.ID, tenant.ID, owner.ID, ownerRole, []string{app.ID}); err != nil {
		t.Fatalf("grant application access: %v", err)
	}

	codeHash := []byte("hashed-authorization-code")
	if err := st.CreateAuthorizationCode(ctx, app.ID, owner.ID, "https://app.example.test/cb", codeHash); err != nil {
		t.Fatalf("create authorization code: %v", err)
	}
	tokenHash := []byte("hashed-session-token")
	if _, _, err := st.ExchangeAuthorizationCode(ctx, app.ClientID, "https://app.example.test/cb", secretHash, codeHash, tokenHash); err != nil {
		t.Fatalf("exchange authorization code: %v", err)
	}

	before, err := st.CountActiveClientSessions(ctx, owner.ID)
	if err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if before != 1 {
		t.Fatalf("active client sessions before logout = %d, want 1", before)
	}

	// A real session cookie, so the handler resolves an identity and takes the
	// revocation path rather than the anonymous one.
	secret := strings.Repeat("s", 32)
	manager := session.New(secret, false)
	server := &Server{
		cfg:      config.Config{BaseURL: "https://auth.example.test", AuthDomain: "auth.example.test"},
		store:    st,
		sessions: manager,
		// The handler logs how many sessions it revoked, so a discard logger is
		// needed rather than leaving it nil.
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	issued := httptest.NewRecorder()
	if err := manager.Set(issued, session.Claims{UserID: owner.ID, Management: true}); err != nil {
		t.Fatalf("issue session: %v", err)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range issued.Result().Cookies() {
		if cookie.Name == "go_loose_session" {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie was issued")
	}

	request := httptest.NewRequest(http.MethodPost, "https://auth.example.test/auth/logout", nil)
	request.AddCookie(sessionCookie)
	response := httptest.NewRecorder()
	server.authLogout(response, request)

	after, err := st.CountActiveClientSessions(ctx, owner.ID)
	if err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if after != 0 {
		t.Fatalf("active client sessions after logout = %d, want 0: the other applications would still accept these tokens", after)
	}

	// The token itself must stop resolving, which is what the tenant application
	// experiences as being signed out.
	if _, err := st.ClientUserByToken(ctx, tokenHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("token still resolves after logout: %v, want ErrNotFound", err)
	}
}

// testDatabaseURL returns a database for the store-backed tests to reset and
// migrate.
//
// It reads its own variable rather than GO_LOOSE_TEST_DATABASE_URL, and defaults to
// a different database again. Go runs package tests in parallel and both packages
// drop every table, so pointing them at one database makes them fight over the
// schema; deriving this from the shared variable would reproduce exactly that.
func testDatabaseURL(t *testing.T) string {
	url := envOr("GO_LOOSE_TEST_SERVER_DATABASE_URL",
		"postgres://goloose:goloose@localhost:5433/goloose_server_test?sslmode=disable")
	requireScratchDatabase(t, url)
	return url
}

// requireScratchDatabase refuses to run against anything that looks like a real
// database, because resetSchema drops every table in the public schema. The
// database name must contain "test" unless the operator opts out explicitly.
func requireScratchDatabase(t *testing.T, rawURL string) {
	t.Helper()
	if os.Getenv("GO_LOOSE_TEST_DATABASE_DESTRUCTIVE") == "1" {
		return
	}
	parsed, err := neturl.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	name := strings.TrimPrefix(parsed.Path, "/")
	if !strings.Contains(strings.ToLower(name), "test") {
		t.Fatalf("refusing to run store-backed tests against database %q: resetSchema drops every table. "+
			"Point it at a scratch database whose name contains \"test\" (run `make integration-db` to create one), "+
			"or set GO_LOOSE_TEST_DATABASE_DESTRUCTIVE=1 to override.", name)
	}
}

// envOr returns the environment value or a fallback.
func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// resetSchema drops every table so a store-backed test starts from the same state a
// fresh installation has. The tables live in a scratch database; the same helper
// exists in the store package's own tests.
func resetSchema(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, name := range tables {
		if _, err := db.ExecContext(ctx, `DROP TABLE IF EXISTS "`+name+`" CASCADE`); err != nil {
			return err
		}
	}
	return nil
}
