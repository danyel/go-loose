package behaviour

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// journey carries the identifiers one phase creates into the phases that use
// them, so each phase reads like a step a person would take.
type journey struct {
	t          *testing.T
	h          *harness
	admin      *browser
	adminEmail string

	tenantID          string
	tenantSlug        string
	scopedTenant      string
	scopedTenantID    string
	applicationID     string
	clientID          string
	clientSecret      string
	apiKey            string
	apiKeyID          string
	contractID        string
	customRoleID      string
	permission        string
	memberEmail       string
	memberPassword    string
	ungrantedEmail    string
	ungrantedPassword string
	ungrantedMemberID string
	memberID          string
	userRoleID        string
	viewerRoleID      string
	avatarKey         string
	accessToken       string
	profileName       string
}

// browser returns a fresh, signed-out visitor pointed at the current instance.
func (j *journey) browser() *browser { return newBrowser(j.t, j.h.addr) }

// restart replaces the running process and points the signed-in browser at the new
// one. The cookie jar is kept deliberately: it is the same person, and their
// session cookie is scoped to the host rather than to the port.
func (j *journey) restart(databaseURL string) {
	j.h = j.h.restart(databaseURL)
	if j.admin != nil {
		j.admin.addr = j.h.addr
	}
}

// adminHost is the tenant hostname the local administrator belongs to.
func (j *journey) adminHost() string { return j.h.tenantHost(j.tenantSlug) }

// phase runs one step. Steps run in order and share state, which is why this is
// a single test with subtests rather than a set of independent ones.
func phase(t *testing.T, name string, step func(t *testing.T)) {
	t.Helper()
	t.Run(name, step)
}

func requireScratchDatabase(t *testing.T, databaseURL string) {
	t.Helper()
	if os.Getenv("GO_LOOSE_BEHAVIOUR_DESTRUCTIVE") == "1" {
		return
	}
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse database URL: %v", err)
	}
	name := strings.TrimPrefix(parsed.Path, "/")
	if !strings.Contains(strings.ToLower(name), "test") {
		t.Fatalf("refusing to run against database %q: the suite drops every table. "+
			"Point GO_LOOSE_BEHAVIOUR_DATABASE_URL at a scratch database whose name contains \"test\".", name)
	}
}

// TestApplicationBehaviour walks the entire application once, in the order a
// person would: install it, sign in, build out a tenant, wire an application,
// manage people and roles, edit a profile, then replace the process and check
// that everything is still there.
func TestApplicationBehaviour(t *testing.T) {
	if os.Getenv("GO_LOOSE_BEHAVIOUR") != "1" {
		t.Skip("set GO_LOOSE_BEHAVIOUR=1 and GO_LOOSE_BEHAVIOUR_DATABASE_URL to run the behaviour suite")
	}
	databaseURL := os.Getenv("GO_LOOSE_BEHAVIOUR_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set GO_LOOSE_BEHAVIOUR_DATABASE_URL to a scratch database")
	}
	requireScratchDatabase(t, databaseURL)

	// Start from nothing: the suite is meant to prove a first install works.
	resetDatabase(t, databaseURL)

	credentials := loadGoogleCredentials(t)
	j := &journey{t: t, h: start(t, databaseURL, false), adminEmail: localAdminMail}
	j.admin = j.browser()

	installPhases(t, j, credentials)

	// The operator now adds the local administrator and restarts, which is also the
	// first proof that the installation survived the process it was written by.
	j.restart(databaseURL)
	authenticationPhases(t, j)
	consolePhases(t, j)
	tenantPhases(t, j)
	applicationPhases(t, j)
	contractPhases(t, j)
	membershipPhases(t, j)
	clientLoginPhases(t, j)
	rolePhases(t, j)
	profilePhases(t, j)
	securityPhases(t, j)
	persistencePhases(t, j)
}

// installPhases drives the first-run installer with the real Google credentials
// and then checks what reached PostgreSQL.
func installPhases(t *testing.T, j *journey, credentials googleCredentials) {
	t.Helper()

	phase(t, "an uninstalled instance sends the console to the installer", func(t *testing.T) {
		response := j.browser().get(j.h.apex(), "/", nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303", response.StatusCode)
		}
		if got := location(t, response); got != "/install" {
			t.Fatalf("redirect = %q, want /install", got)
		}
	})

	phase(t, "the installer refuses a submission without its CSRF token", func(t *testing.T) {
		browser := j.browser()
		page := bodyOf(t, browser.get(j.h.apex(), "/install", nil))
		token := csrfFrom(t, page)
		// The cookie was issued for the page, so the mismatch below is the token,
		// not a missing cookie.
		browser.cookies = map[string]map[string]*http.Cookie{}
		response := browser.form(j.h.apex(), "/install", url.Values{
			"csrf_token": {token}, "field1": {"https://accounts.google.com"},
			"field2": {credentials.ClientID}, "field3": {credentials.ClientSecret},
			"field4": {j.h.baseURL + "/auth/callback"},
		}, nil)
		statusOnly(t, response, http.StatusForbidden)
	})

	phase(t, "the installer refuses an incomplete submission", func(t *testing.T) {
		browser := j.browser()
		token := csrfFrom(t, bodyOf(t, browser.get(j.h.apex(), "/install", nil)))
		response := browser.form(j.h.apex(), "/install", url.Values{
			"csrf_token": {token}, "field1": {"https://accounts.google.com"},
		}, nil)
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "installing stores the provider settings and seeds the demo data", func(t *testing.T) {
		browser := j.browser()
		token := csrfFrom(t, bodyOf(t, browser.get(j.h.apex(), "/install", nil)))
		response := browser.form(j.h.apex(), "/install", url.Values{
			"csrf_token": {token},
			"field1":     {"https://accounts.google.com"},
			"field2":     {credentials.ClientID},
			"field3":     {credentials.ClientSecret},
			"field4":     {j.h.baseURL + "/auth/callback"},
			"seed_demo":  {"on"},
		}, nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303: %s", response.StatusCode, bodyOf(t, response))
		}
		if got := location(t, response); got != "/auth/start" {
			t.Fatalf("redirect = %q, want /auth/start", got)
		}

		var issuer, clientID, ciphertext, redirect string
		var seeded bool
		row := j.h.db.QueryRowContext(t.Context(), `
			SELECT oidc_issuer, oidc_client_id, encode(oidc_client_secret_ciphertext, 'escape'), oidc_redirect_url, seeded_demo
			FROM installation_settings WHERE singleton`)
		if err := row.Scan(&issuer, &clientID, &ciphertext, &redirect, &seeded); err != nil {
			t.Fatalf("read installation_settings: %v", err)
		}
		if issuer != "https://accounts.google.com" {
			t.Errorf("issuer = %q", issuer)
		}
		if clientID != credentials.ClientID {
			t.Errorf("client id = %q, want the credentials from google_secrets.json", clientID)
		}
		if redirect != j.h.baseURL+"/auth/callback" {
			t.Errorf("redirect url = %q", redirect)
		}
		if !seeded {
			t.Error("seeded_demo = false, want true")
		}
		// The secret must be encrypted at rest, never the plaintext from the form.
		if strings.Contains(ciphertext, credentials.ClientSecret) {
			t.Error("the client secret is stored in plaintext")
		}
		if ciphertext == "" {
			t.Error("the client secret was not stored")
		}

		for _, want := range []string{"nmbs", "ypto"} {
			var slug string
			if err := j.h.db.QueryRowContext(t.Context(),
				`SELECT slug FROM tenants WHERE slug = $1`, want).Scan(&slug); err != nil {
				t.Errorf("tenant %s was not seeded: %v", want, err)
			}
		}
		var demoUsers int
		if err := j.h.db.QueryRowContext(t.Context(),
			`SELECT count(*) FROM users WHERE email LIKE '%@nmbs.auth.dev' OR email LIKE '%@ypto.auth.dev'`).
			Scan(&demoUsers); err != nil {
			t.Fatalf("count demo users: %v", err)
		}
		if demoUsers != 4 {
			t.Errorf("demo users = %d, want 4", demoUsers)
		}
	})

	phase(t, "an installed instance no longer offers the installer", func(t *testing.T) {
		browser := j.browser()
		response := browser.get(j.h.apex(), "/install", nil)
		if response.StatusCode != http.StatusSeeOther || location(t, response) != "/login" {
			t.Fatalf("GET /install = %d %q, want 303 to /login", response.StatusCode, response.Header.Get("Location"))
		}
		token := csrfFrom(t, bodyOf(t, browser.get(j.h.apex(), "/login", nil)))
		response = browser.form(j.h.apex(), "/install", url.Values{
			"csrf_token": {token}, "field1": {"https://accounts.google.com"},
			"field2": {credentials.ClientID}, "field3": {credentials.ClientSecret},
			"field4": {j.h.baseURL + "/auth/callback"},
		}, nil)
		statusOnly(t, response, http.StatusConflict)
	})

	phase(t, "sign-in redirects to Google with the installed client id", func(t *testing.T) {
		browser := j.browser()
		response := browser.get(j.h.apex(), "/auth/start", nil)
		if response.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want 302: %s", response.StatusCode, bodyOf(t, response))
		}
		provider, err := url.Parse(location(t, response))
		if err != nil {
			t.Fatalf("parse provider URL: %v", err)
		}
		if provider.Host != "accounts.google.com" {
			t.Errorf("provider host = %q, want accounts.google.com", provider.Host)
		}
		query := provider.Query()
		if got := query.Get("client_id"); got != credentials.ClientID {
			t.Errorf("client_id = %q, want the installed credentials", got)
		}
		if got := query.Get("redirect_uri"); got != j.h.baseURL+"/auth/callback" {
			t.Errorf("redirect_uri = %q", got)
		}
		if query.Get("response_type") != "code" {
			t.Errorf("response_type = %q, want code", query.Get("response_type"))
		}
		// The signed state must be echoed back to the callback.
		if query.Get("state") == "" {
			t.Error("no state parameter in the provider redirect")
		}
	})

	phase(t, "the callback refuses a forged state", func(t *testing.T) {
		browser := j.browser()
		browser.get(j.h.apex(), "/auth/start", nil)
		response := browser.get(j.h.apex(), "/auth/callback?code=fake&state=forged", nil)
		statusOnly(t, response, http.StatusBadRequest)
	})
}

// authenticationPhases signs in as the bootstrapped local administrator and checks
// that the session is a real one.
func authenticationPhases(t *testing.T, j *journey) {
	t.Helper()
	j.tenantSlug = "nmbs"

	phase(t, "the sign-in page is served on the tenant host", func(t *testing.T) {
		host := j.adminHost()
		page := bodyOf(t, j.browser().get(host, "/login", nil))
		if !strings.Contains(page, "NMBS") {
			t.Errorf("the sign-in page does not mention the tenant: %.200s", page)
		}
	})

	phase(t, "a wrong password is rejected", func(t *testing.T) {
		browser := j.browser()
		host := j.adminHost()
		token := csrfFrom(t, bodyOf(t, browser.get(host, "/login", nil)))
		response := browser.form(host, "/auth/password", url.Values{
			"csrf_token": {token}, "email": {localAdminMail}, "password": {"wrong-password-entirely"},
		}, nil)
		statusOnly(t, response, http.StatusUnauthorized)
	})

	phase(t, "password sign-in without a CSRF token is rejected", func(t *testing.T) {
		browser := j.browser()
		host := j.adminHost()
		bodyOf(t, browser.get(host, "/login", nil))
		response := browser.form(host, "/auth/password", url.Values{
			"email": {localAdminMail}, "password": {localAdminPass},
		}, nil)
		statusOnly(t, response, http.StatusForbidden)
	})

	phase(t, "repeated failures lock the account out", func(t *testing.T) {
		// A distinct address keeps the lockout away from the other sign-ins.
		browser := j.browser()
		host := j.adminHost()
		token := csrfFrom(t, bodyOf(t, browser.get(host, "/login", nil)))
		locked := false
		for attempt := 0; attempt < 6; attempt++ {
			response := browser.form(host, "/auth/password", url.Values{
				"csrf_token": {token}, "email": {"lockout@auth.test"}, "password": {"nope-nope-nope"},
			}, nil)
			response.Body.Close()
			if response.StatusCode == http.StatusTooManyRequests {
				locked = true
				break
			}
		}
		if !locked {
			t.Error("six wrong passwords never produced a 429")
		}
	})

	phase(t, "the administrator signs in and reaches the console", func(t *testing.T) {
		browser := j.browser()
		host := j.adminHost()
		token := csrfFrom(t, bodyOf(t, browser.get(host, "/login", nil)))
		response := browser.form(host, "/auth/password", url.Values{
			"csrf_token": {token}, "email": {localAdminMail}, "password": {localAdminPass},
		}, nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303: %s", response.StatusCode, bodyOf(t, response))
		}
		if got := location(t, response); got != "/" {
			t.Fatalf("redirect = %q, want /", got)
		}
		j.admin = browser

		page := bodyOf(t, j.admin.get(j.adminHost(), "/", nil))
		if !strings.Contains(page, "<html") {
			t.Error("the console page is not HTML")
		}
	})

	phase(t, "the management session does not leak to the apex host", func(t *testing.T) {
		// The session cookie is issued without a Domain, so it belongs to the host
		// that signed in. That is deliberate: a tenant session must not be usable on
		// the installation-wide host.
		response := j.admin.get(j.h.apex(), "/api/v1/dashboard", nil)
		statusOnly(t, response, http.StatusUnauthorized)
	})

	phase(t, "the session is refused without its cookie", func(t *testing.T) {
		stranger := j.browser()
		response := stranger.get(j.adminHost(), "/api/v1/dashboard", nil)
		statusOnly(t, response, http.StatusUnauthorized)
	})
}

// consolePhases checks that every console screen and its data load.
func consolePhases(t *testing.T, j *journey) {
	t.Helper()

	phase(t, "the dashboard reports the installed state", func(t *testing.T) {
		type dashboard struct {
			Tenants             []map[string]any `json:"tenants"`
			Applications        []map[string]any `json:"applications"`
			Keys                []map[string]any `json:"keys"`
			Contracts           []map[string]any `json:"contracts"`
			Users               []map[string]any `json:"users"`
			PendingUsers        []map[string]any `json:"pending_users"`
			Permissions         []map[string]any `json:"permissions"`
			Profile             map[string]any   `json:"profile"`
			SystemAdministrator bool             `json:"is_system_administrator"`
		}
		response := j.admin.get(j.adminHost(), "/api/v1/dashboard", nil)
		data := decode[dashboard](t, response, http.StatusOK)
		if len(data.Tenants) == 0 {
			t.Error("the dashboard lists no tenants")
		}
		if len(data.Permissions) == 0 {
			t.Error("the dashboard lists no permissions")
		}
		if data.Profile["email"] != localAdminMail {
			t.Errorf("profile email = %v, want %s", data.Profile["email"], localAdminMail)
		}
		if !data.SystemAdministrator {
			t.Error("the bootstrapped administrator is not reported as a system administrator")
		}
		// Find the tenant this journey works in.
		for _, tenant := range data.Tenants {
			if tenant["slug"] == j.tenantSlug {
				j.tenantID, _ = tenant["id"].(string)
			}
		}
		if j.tenantID == "" {
			t.Fatalf("tenant %s is missing from the dashboard: %v", j.tenantSlug, data.Tenants)
		}
	})

	phase(t, "every console screen is served", func(t *testing.T) {
		for _, path := range []string{"/", "/profile", "/roles", "/docs", "/openapi.json"} {
			page := bodyOf(t, j.admin.get(j.adminHost(), path, nil))
			if !strings.Contains(page, "<html") && path != "/openapi.json" {
				t.Errorf("%s did not return a page", path)
			}
		}
	})

	phase(t, "every script and stylesheet is served and nothing else is", func(t *testing.T) {
		for _, asset := range []string{"style.css", "app.js", "profile.js", "roles.js", "account.js"} {
			response := j.admin.get(j.adminHost(), "/assets/"+asset, nil)
			if response.StatusCode != http.StatusOK {
				t.Errorf("GET /assets/%s = %d", asset, response.StatusCode)
			}
			response.Body.Close()
		}
		for _, asset := range []string{"secret.js", "style.css.map"} {
			response := j.admin.get(j.adminHost(), "/assets/"+asset, nil)
			if response.StatusCode != http.StatusNotFound {
				t.Errorf("GET /assets/%s = %d, want 404", asset, response.StatusCode)
			}
			response.Body.Close()
		}
	})

	phase(t, "the published specification is valid JSON", func(t *testing.T) {
		var spec map[string]any
		if err := json.Unmarshal([]byte(bodyOf(t, j.admin.get(j.adminHost(), "/openapi.json", nil))), &spec); err != nil {
			t.Fatalf("parse openapi.json: %v", err)
		}
		if _, ok := spec["paths"]; !ok {
			t.Error("the specification has no paths")
		}
	})
}

// pngBase64 is a tiny valid PNG used for the profile picture flows, and
// decodeBase64PNG returns the same bytes for checks that need the raw image.
const pngBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg=="

func decodeBase64PNG(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(pngBase64)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return raw
}

var _ = sql.ErrNoRows

// The remaining phases are defined in their own files so each one stays
// readable: tenant, application, contract, client login, role, membership,
// profile, security, and persistence.
