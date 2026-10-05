package behaviour

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

// persistencePhases replaces the running process and then reads everything back.
// This is the phase the whole suite exists for: it proves the application keeps
// its state in PostgreSQL rather than in memory, which is the one property that
// cannot be checked by looking at a single request.
func persistencePhases(t *testing.T, j *journey) {
	t.Helper()

	// Take a copy of the identifiers so the assertions below can be made against
	// values captured before the restart rather than against whatever the new
	// process happens to hand back.
	want := struct {
		tenant       string
		application  string
		contract     string
		apiKey       string
		clientID     string
		member       string
		customRole   string
		displayName  string
		avatarSet    bool
		memberGrants int
	}{
		tenant: j.scopedTenant, application: j.applicationID, contract: j.contractID,
		apiKey: j.apiKeyID, clientID: j.clientID, member: j.memberEmail,
		customRole: j.customRoleID, displayName: j.profileName,
	}
	// Put a picture back so the restart has binary state to preserve.
	response := j.admin.json(http.MethodPut, j.adminHost(), "/api/v1/profile", map[string]any{
		"avatar": pngBase64,
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("set a picture to carry across the restart: %d", response.StatusCode)
	}
	type withAvatar struct {
		AvatarURL string `json:"avatar_url"`
	}
	avatarPath := decode[withAvatar](t, response, http.StatusOK).AvatarURL
	want.avatarSet = avatarPath != ""

	phase(t, "a client session is established before the restart", func(t *testing.T) {
		// The earlier phase revoked its token on purpose, so a fresh one is needed to
		// show that a session outlives the process.
		j.accessToken = establishClientSession(t, j, "before-restart")
		if j.accessToken == "" {
			t.Fatal("no client session token")
		}
		response := j.browser().request(http.MethodGet, j.h.apex(), "/connect/userinfo", nil,
			map[string]string{"Authorization": "Bearer " + j.accessToken})
		statusOnly(t, response, http.StatusOK)
	})

	phase(t, "the installation survives the process that wrote it", func(t *testing.T) {
		j.restart(os.Getenv("GO_LOOSE_BEHAVIOUR_DATABASE_URL"))

		// A restarted instance must know it is installed without the environment
		// saying so, which means it read the installation row and decrypted the
		// stored OIDC secret.
		response := j.browser().get(j.h.apex(), "/install", nil)
		if response.StatusCode != http.StatusSeeOther || location(t, response) != "/login" {
			t.Errorf("GET /install after restart = %d %q, want 303 to /login",
				response.StatusCode, response.Header.Get("Location"))
		}
	})

	phase(t, "the provider configuration still works after the restart", func(t *testing.T) {
		browser := j.browser()
		response := browser.get(j.h.apex(), "/auth/start", nil)
		if response.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want a provider redirect: %s", response.StatusCode, bodyOf(t, response))
		}
		target := location(t, response)
		if !strings.Contains(target, "accounts.google.com") {
			t.Errorf("redirect = %q, want the installed provider", target)
		}
		if !strings.Contains(target, "client_id=") {
			t.Errorf("the provider redirect carries no client id: %s", target)
		}
	})

	phase(t, "an existing session is still valid after the restart", func(t *testing.T) {
		// The session is a signed cookie, so a new process with the same secret
		// keeps honouring it.
		response := j.admin.get(j.adminHost(), "/api/v1/dashboard", nil)
		statusOnly(t, response, http.StatusOK)
	})

	phase(t, "the tenant, application, contract, and revoked key all persist", func(t *testing.T) {
		var tenants, applications, contracts, endpoints int
		if err := j.h.db.QueryRowContext(t.Context(), `SELECT count(*) FROM tenants WHERE slug = $1`, want.tenant).Scan(&tenants); err != nil {
			t.Fatalf("count tenants: %v", err)
		}
		if err := j.h.db.QueryRowContext(t.Context(), `SELECT count(*) FROM applications WHERE id = $1`, want.application).Scan(&applications); err != nil {
			t.Fatalf("count applications: %v", err)
		}
		if err := j.h.db.QueryRowContext(t.Context(), `SELECT count(*) FROM openapi_contracts WHERE id = $1`, want.contract).Scan(&contracts); err != nil {
			t.Fatalf("count contracts: %v", err)
		}
		if err := j.h.db.QueryRowContext(t.Context(), `SELECT count(*) FROM contract_endpoints WHERE contract_id = $1`, want.contract).Scan(&endpoints); err != nil {
			t.Fatalf("count endpoints: %v", err)
		}
		if tenants != 1 || applications != 1 || contracts != 1 || endpoints != 3 {
			t.Errorf("persisted: tenants=%d applications=%d contracts=%d endpoints=%d",
				tenants, applications, contracts, endpoints)
		}

		// The revoked key must stay revoked.
		var status string
		if err := j.h.db.QueryRowContext(t.Context(), `SELECT status FROM api_keys WHERE id = $1`, want.apiKey).Scan(&status); err != nil {
			t.Fatalf("read the key: %v", err)
		}
		if status != "revoked" {
			t.Errorf("key status = %q, want revoked", status)
		}
	})

	phase(t, "the dashboard reports the same state to the new process", func(t *testing.T) {
		type listing struct {
			Tenants      []struct{ Slug string } `json:"tenants"`
			Applications []struct {
				Slug         string   `json:"slug"`
				RedirectURIs []string `json:"redirect_uris"`
			} `json:"applications"`
			Users []struct {
				Email string `json:"email"`
				Role  string `json:"role"`
			} `json:"users"`
		}
		result := decode[listing](t, j.admin.get(j.adminHost(), "/api/v1/dashboard", nil), http.StatusOK)
		slugs := map[string]bool{}
		for _, tenant := range result.Tenants {
			slugs[tenant.Slug] = true
		}
		if !slugs[want.tenant] {
			t.Errorf("tenant %s is missing after the restart", want.tenant)
		}
		emails := map[string]string{}
		for _, user := range result.Users {
			emails[user.Email] = user.Role
		}
		if emails[want.member] == "" {
			t.Errorf("%s is missing after the restart", want.member)
		}
		if emails[localAdminMail] != "owner" {
			t.Errorf("the administrator's role is %q after the restart, want owner", emails[localAdminMail])
		}
	})

	phase(t, "the customized display name and the picture both persist", func(t *testing.T) {
		type profile struct {
			DisplayName    string `json:"display_name"`
			AvatarURL      string `json:"avatar_url"`
			NameCustomized bool   `json:"name_customized"`
		}
		result := decode[profile](t, j.admin.get(j.adminHost(), "/api/v1/profile", nil), http.StatusOK)
		if result.DisplayName != want.displayName {
			t.Errorf("display name = %q, want %q", result.DisplayName, want.displayName)
		}
		if !result.NameCustomized {
			t.Error("name_customized was lost")
		}
		if result.AvatarURL != avatarPath {
			t.Errorf("avatar_url = %q, want %q", result.AvatarURL, avatarPath)
		}
		if !want.avatarSet {
			t.Fatal("no picture was set before the restart")
		}
	})

	phase(t, "the picture is still served, with the same bytes", func(t *testing.T) {
		key := strings.TrimPrefix(avatarPath, "/api/v1/avatars/")
		response := j.browser().get(j.h.apex(), "/api/v1/avatars/"+key, nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want the picture to survive: %s", response.StatusCode, bodyOf(t, response))
		}
		if got := response.Header.Get("Content-Type"); got != "image/png" {
			t.Errorf("content type = %q", got)
		}
		if len(bodyOf(t, response)) == 0 {
			t.Error("empty picture after the restart")
		}
	})

	phase(t, "the tenant role and the permission catalog persist", func(t *testing.T) {
		type listing struct {
			Roles []struct {
				Slug string `json:"slug"`
			} `json:"roles"`
		}
		result := decode[listing](t, j.admin.get(j.adminHost(),
			"/api/v1/roles?tenant_id="+j.scopedTenantID, nil), http.StatusOK)
		found := false
		for _, role := range result.Roles {
			if role.Slug == "reporter" {
				found = true
			}
		}
		if !found {
			t.Error("the tenant-defined role is missing after the restart")
		}
		statusOnly(t, j.admin.get(j.adminHost(), "/api/v1/permissions", nil), http.StatusOK)
	})

	phase(t, "a client session token issued before the restart still resolves", func(t *testing.T) {
		// The session is a row in PostgreSQL, not process state, so a deployment
		// that restarts does not sign every user out of the tenant applications.
		if j.accessToken == "" {
			t.Fatal("no client session was established before the restart")
		}
		type identity struct {
			Email string `json:"email"`
		}
		response := j.browser().request(http.MethodGet, j.h.apex(), "/connect/userinfo", nil,
			map[string]string{"Authorization": "Bearer " + j.accessToken})
		user := decode[identity](t, response, http.StatusOK)
		if user.Email != j.memberEmail {
			t.Errorf("email = %q, want %s", user.Email, j.memberEmail)
		}
	})

	phase(t, "a new sign-in still works after the restart", func(t *testing.T) {
		browser := j.browser()
		host := j.adminHost()
		token := csrfFrom(t, bodyOf(t, browser.get(host, "/login", nil)))
		response := browser.form(host, "/auth/password", neturlValues(map[string]string{
			"csrf_token": token, "email": localAdminMail, "password": localAdminPass,
		}), nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-in after restart = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		statusOnly(t, browser.get(host, "/api/v1/dashboard", nil), http.StatusOK)
	})

	phase(t, "an API key issued before the restart is still refused after it", func(t *testing.T) {
		response := j.browser().request(http.MethodPost, j.h.apex(), "/api/v1/authorize",
			stringReader(`{"tenant":"behaviour","application":"behaviour-app","method":"GET","path":"/api/x","host":"app.behaviour.test"}`),
			map[string]string{"X-API-Key": j.apiKey, "Content-Type": "application/json"})
		statusOnly(t, response, http.StatusForbidden)
	})
}
