package behaviour

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// unknownButWellFormed has the shape of a real key so that it reaches the store
// and is rejected as unknown, rather than being turned away by format validation.
var unknownButWellFormed = "gl_unknown_" + strings.Repeat("A", 40)

// applicationPhases registers an application, issues API keys, and exercises the
// authorization endpoint that every Go middleware integration depends on.
func applicationPhases(t *testing.T, j *journey) {
	t.Helper()
	host := j.adminHost()

	phase(t, "an application is registered with allowed hosts", func(t *testing.T) {
		type application struct {
			ID           string   `json:"id"`
			Slug         string   `json:"slug"`
			Name         string   `json:"name"`
			AllowedHosts []string `json:"allowed_hosts"`
		}
		response := j.admin.json(http.MethodPost, host, "/api/v1/applications", map[string]any{
			"tenant_id": j.scopedTenantID, "slug": "behaviour-app", "name": "Behaviour App",
			"description": "created by the behaviour suite", "allowed_hosts": []string{"app.behaviour.test"},
		})
		created := decode[application](t, response, http.StatusCreated)
		if created.Slug != "behaviour-app" {
			t.Errorf("slug = %q", created.Slug)
		}
		j.applicationID = created.ID
	})

	phase(t, "an allowed host carrying a scheme or port is refused", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, host, "/api/v1/applications", map[string]any{
			"tenant_id": j.scopedTenantID, "slug": "bad-hosts", "name": "Bad Hosts",
			"allowed_hosts": []string{"https://app.behaviour.test"},
		})
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "an application without a tenant or a valid slug is refused", func(t *testing.T) {
		for _, payload := range []map[string]any{
			{"slug": "no-tenant", "name": "No Tenant"},
			{"tenant_id": j.scopedTenantID, "slug": "Bad Slug", "name": "Bad Slug"},
			{"tenant_id": j.scopedTenantID, "slug": "", "name": "Empty Slug"},
		} {
			response := j.admin.json(http.MethodPost, host, "/api/v1/applications", payload)
			statusOnly(t, response, http.StatusBadRequest)
		}
	})

	phase(t, "an API key is issued and shown exactly once", func(t *testing.T) {
		type issued struct {
			Key struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"key"`
			Secret string `json:"secret"`
		}
		response := j.admin.json(http.MethodPost, host, "/api/v1/keys", map[string]any{
			"application_id": j.applicationID, "name": "integration key",
		})
		result := decode[issued](t, response, http.StatusCreated)
		if result.Secret == "" {
			t.Fatal("no secret returned")
		}
		if result.Key.ID == "" {
			t.Error("no key id returned")
		}
		j.apiKey, j.apiKeyID = result.Secret, result.Key.ID

		// The dashboard must never expose the secret again.
		type keyListing struct {
			Keys []map[string]any `json:"keys"`
		}
		listing := decode[keyListing](t, j.admin.get(host, "/api/v1/dashboard", nil), http.StatusOK)
		for _, key := range listing.Keys {
			for field, value := range key {
				if text, ok := value.(string); ok && text == j.apiKey {
					t.Errorf("the dashboard leaked the secret in %q", field)
				}
			}
		}
	})

	phase(t, "a key in the wrong format is refused", func(t *testing.T) {
		response := j.admin.request(http.MethodPost, j.h.apex(), "/api/v1/authorize",
			nil, map[string]string{"X-API-Key": "not-a-key"})
		// The authorize endpoint is reached by application middleware, not by a
		// browser session, so no session is involved here.
		statusOnly(t, response, http.StatusUnauthorized)
	})

	phase(t, "an unknown key is denied", func(t *testing.T) {
		response := j.admin.request(http.MethodPost, j.h.apex(), "/api/v1/authorize",
			stringReader(fmt.Sprintf(`{"tenant":%q,"application":"behaviour-app","method":"GET","path":"/api/x","host":"app.behaviour.test"}`, j.scopedTenant)),
			map[string]string{"X-API-Key": unknownButWellFormed, "Content-Type": "application/json"})
		statusOnly(t, response, http.StatusForbidden)
	})

	phase(t, "a valid key is authorized for its own tenant, application, and host", func(t *testing.T) {
		type decision struct {
			Allowed    bool   `json:"allowed"`
			Reason     string `json:"reason"`
			TenantSlug string `json:"tenant_slug"`
			AppSlug    string `json:"application_slug"`
			APIKeyName string `json:"api_key_name"`
		}
		response := j.admin.request(http.MethodPost, j.h.apex(), "/api/v1/authorize",
			stringReader(fmt.Sprintf(`{"tenant":%q,"application":"behaviour-app","method":"GET","path":"/api/x","host":"app.behaviour.test"}`, j.scopedTenant)),
			map[string]string{"X-API-Key": j.apiKey, "Content-Type": "application/json"})
		result := decode[decision](t, response, http.StatusOK)
		if !result.Allowed {
			t.Errorf("allowed = false, reason %q", result.Reason)
		}
		if result.TenantSlug != "behaviour" || result.AppSlug != "behaviour-app" {
			t.Errorf("identity = %s/%s", result.TenantSlug, result.AppSlug)
		}
		if result.APIKeyName != "integration key" {
			t.Errorf("key name = %q", result.APIKeyName)
		}
	})

	phase(t, "a host outside the allow list is denied", func(t *testing.T) {
		response := j.admin.request(http.MethodPost, j.h.apex(), "/api/v1/authorize",
			stringReader(`{"tenant":"{j.scopedTenant}","application":"behaviour-app","method":"GET","path":"/api/x","host":"evil.test"}`),
			map[string]string{"X-API-Key": j.apiKey, "Content-Type": "application/json"})
		statusOnly(t, response, http.StatusForbidden)
	})

	phase(t, "another tenant is not reachable with this key", func(t *testing.T) {
		response := j.admin.request(http.MethodPost, j.h.apex(), "/api/v1/authorize",
			stringReader(fmt.Sprintf(`{"tenant":%q,"application":"behaviour-app","method":"GET","path":"/api/x","host":"app.behaviour.test"}`, j.tenantSlug)),
			map[string]string{"X-API-Key": j.apiKey, "Content-Type": "application/json"})
		statusOnly(t, response, http.StatusForbidden)
	})

	phase(t, "the key can also be presented as a bearer token", func(t *testing.T) {
		response := j.admin.request(http.MethodPost, j.h.apex(), "/api/v1/authorize",
			stringReader(fmt.Sprintf(`{"tenant":%q,"application":"behaviour-app","method":"GET","path":"/api/x","host":"app.behaviour.test"}`, j.scopedTenant)),
			map[string]string{"Authorization": "Bearer " + j.apiKey, "Content-Type": "application/json"})
		statusOnly(t, response, http.StatusOK)
	})

	phase(t, "an incomplete authorization request is refused", func(t *testing.T) {
		response := j.admin.request(http.MethodPost, j.h.apex(), "/api/v1/authorize",
			stringReader(`{"method":"GET"}`),
			map[string]string{"X-API-Key": j.apiKey, "Content-Type": "application/json"})
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "every authorization attempt is recorded", func(t *testing.T) {
		var total int
		if err := j.h.db.QueryRowContext(t.Context(),
			`SELECT count(*) FROM authorization_events WHERE api_key_id = $1`, j.apiKeyID).Scan(&total); err != nil {
			t.Fatalf("count authorization events: %v", err)
		}
		if total < 4 {
			t.Errorf("authorization events = %d, want the attempts above to be recorded", total)
		}
	})

	phase(t, "revoking the key stops it working immediately", func(t *testing.T) {
		response := j.admin.request(http.MethodPost, j.adminHost(),
			"/api/v1/keys/"+j.apiKeyID+"/revoke", nil, map[string]string{
				"Origin": "http://" + j.adminHost(), "Content-Length": "0",
			})
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("revoke = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		response.Body.Close()

		response = j.admin.request(http.MethodPost, j.h.apex(), "/api/v1/authorize",
			stringReader(fmt.Sprintf(`{"tenant":%q,"application":"behaviour-app","method":"GET","path":"/api/x","host":"app.behaviour.test"}`, j.scopedTenant)),
			map[string]string{"X-API-Key": j.apiKey, "Content-Type": "application/json"})
		statusOnly(t, response, http.StatusForbidden)
	})

	phase(t, "revoking an unknown key reports not found", func(t *testing.T) {
		response := j.admin.request(http.MethodPost, j.adminHost(),
			"/api/v1/keys/00000000-0000-0000-0000-000000000000/revoke", nil, map[string]string{
				"Origin": "http://" + j.adminHost(), "Content-Length": "0",
			})
		statusOnly(t, response, http.StatusNotFound)
	})
}
