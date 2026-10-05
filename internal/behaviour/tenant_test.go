package behaviour

import (
	"net/http"
	"net/url"
	"testing"
)

// neturlValues builds a form body from plain strings, so phases do not have to
// repeat the url.Values literal for every field.
func neturlValues(fields map[string]string) url.Values {
	values := url.Values{}
	for name, value := range fields {
		values.Set(name, value)
	}
	return values
}

// tenantPhases exercises the installation-wide tenant management, which is the
// one console action restricted to system administrators.
func tenantPhases(t *testing.T, j *journey) {
	t.Helper()

	phase(t, "a system administrator creates a tenant", func(t *testing.T) {
		type tenant struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
			Name string `json:"name"`
		}
		response := j.admin.json(http.MethodPost, j.adminHost(), "/api/v1/tenants", map[string]string{
			"slug": "behaviour", "name": "Behaviour Tenant",
		})
		created := decode[tenant](t, response, http.StatusCreated)
		if created.Slug != "behaviour" {
			t.Errorf("slug = %q", created.Slug)
		}
		if created.ID == "" {
			t.Error("no tenant id returned")
		}
		// Later phases build their own application in this tenant, so it isolates
		// authorization from the seeded demonstration tenant.
		j.scopedTenant, j.scopedTenantID = created.Slug, created.ID
	})

	phase(t, "a duplicate tenant slug is refused", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, j.adminHost(), "/api/v1/tenants", map[string]string{
			"slug": "behaviour", "name": "Duplicate",
		})
		statusOnly(t, response, http.StatusConflict)
	})

	phase(t, "a malformed tenant slug is refused", func(t *testing.T) {
		for _, slug := range []string{"Has Uppercase", "has/slash", "-leading", ""} {
			response := j.admin.json(http.MethodPost, j.adminHost(), "/api/v1/tenants", map[string]string{
				"slug": slug, "name": "Invalid",
			})
			statusOnly(t, response, http.StatusBadRequest)
		}
	})

	phase(t, "a tenant administrator cannot create a tenant", func(t *testing.T) {
		// The seeded NMBS interviewer is a tenant administrator, not a system one.
		browser := j.browser()
		host := j.adminHost()
		token := csrfFrom(t, bodyOf(t, browser.get(host, "/login", nil)))
		response := browser.form(host, "/auth/password", neturlValues(map[string]string{
			"csrf_token": token, "email": "interview@nmbs.auth.dev", "password": "admin123",
		}), nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("seeded administrator sign-in = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		response = browser.json(http.MethodPost, host, "/api/v1/tenants", map[string]string{
			"slug": "unauthorised", "name": "Unauthorised",
		})
		statusOnly(t, response, http.StatusForbidden)
	})
}
