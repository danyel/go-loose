package behaviour

import (
	"net/http"
	"strings"
	"testing"
)

// securityPhases checks the defences that sit in front of every flow above.
func securityPhases(t *testing.T, j *journey) {
	t.Helper()
	host := j.adminHost()

	phase(t, "a write from another origin is refused", func(t *testing.T) {
		// The Origin header is what a browser sets and an attacker cannot forge, so
		// this is the check that stops a cross-site form post.
		for _, target := range []struct {
			method string
			path   string
		}{
			{http.MethodPost, "/api/v1/tenants"},
			{http.MethodPut, "/api/v1/profile"},
			{http.MethodPost, "/api/v1/permissions"},
			{http.MethodPost, "/api/v1/applications/" + j.applicationID + "/client-config"},
		} {
			response := j.admin.request(target.method, host, target.path,
				strings.NewReader(`{"slug":"csrf","name":"CSRF"}`), map[string]string{
					"Content-Type": "application/json", "Origin": "https://evil.test",
				})
			if response.StatusCode != http.StatusForbidden {
				t.Errorf("%s %s from a foreign origin = %d, want 403", target.method, target.path, response.StatusCode)
			}
			bodyOf(t, response)
		}
	})

	phase(t, "a write with no origin or referrer is refused", func(t *testing.T) {
		response := j.admin.request(http.MethodPost, host, "/api/v1/tenants",
			strings.NewReader(`{"slug":"noorigin","name":"No Origin"}`), map[string]string{
				"Content-Type": "application/json", "Origin": "", "Referer": "",
			})
		statusOnly(t, response, http.StatusForbidden)
	})

	phase(t, "the configured base URL is also accepted as its own origin", func(t *testing.T) {
		// A deployment reached through a different hostname must still be able to
		// write, or every legitimate form post fails.
		response := j.admin.request(http.MethodPost, host, "/api/v1/tenants",
			strings.NewReader(`{"slug":"viabaseurl","name":"Via Base URL"}`), map[string]string{
				"Content-Type": "application/json", "Origin": j.h.baseURL,
			})
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("status = %d, want 201: %s", response.StatusCode, bodyOf(t, response))
		}
	})

	phase(t, "responses carry the hardening headers", func(t *testing.T) {
		response := j.admin.get(host, "/", nil)
		bodyOf(t, response)
		policy := response.Header.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'self'", "connect-src 'self'", "img-src 'self'"} {
			if !strings.Contains(policy, want) {
				t.Errorf("Content-Security-Policy lacks %q: %s", want, policy)
			}
		}
		if got := response.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q", got)
		}
		// Clickjacking is blocked with X-Frame-Options rather than frame-ancestors.
		if got := response.Header.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("X-Frame-Options = %q, want DENY", got)
		}
		if got := response.Header.Get("Referrer-Policy"); got != "same-origin" {
			t.Errorf("Referrer-Policy = %q", got)
		}
		if got := response.Header.Get("Permissions-Policy"); !strings.Contains(got, "camera=()") {
			t.Errorf("Permissions-Policy = %q", got)
		}
	})

	phase(t, "the health check needs no session", func(t *testing.T) {
		response := j.browser().get(j.h.apex(), "/healthz", nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", response.StatusCode)
		}
		bodyOf(t, response)
	})

	phase(t, "a console API call without a session answers 401 rather than a redirect", func(t *testing.T) {
		// An XHR that receives a 303 to the login page cannot tell it apart from a
		// real result, so the API answers with a status the caller can act on.
		for _, path := range []string{"/api/v1/dashboard", "/api/v1/profile", "/api/v1/permissions"} {
			response := j.browser().get(host, path, nil)
			statusOnly(t, response, http.StatusUnauthorized)
		}
	})

	phase(t, "a console page without a session redirects to sign in", func(t *testing.T) {
		for _, path := range []string{"/", "/profile", "/roles"} {
			response := j.browser().get(host, path, nil)
			if response.StatusCode != http.StatusSeeOther || location(t, response) != "/login" {
				t.Errorf("GET %s = %d %q, want 303 to /login", path, response.StatusCode, response.Header.Get("Location"))
			}
			response.Body.Close()
		}
	})

	phase(t, "signing out ends the management session", func(t *testing.T) {
		browser := j.browser()
		token := csrfFrom(t, bodyOf(t, browser.get(host, "/login", nil)))
		response := browser.form(host, "/auth/password", neturlValues(map[string]string{
			"csrf_token": token, "email": localAdminMail, "password": localAdminPass,
		}), nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-in = %d", response.StatusCode)
		}
		response.Body.Close()
		statusOnly(t, browser.get(host, "/api/v1/dashboard", nil), http.StatusOK)

		response = browser.form(host, "/auth/logout", neturlValues(map[string]string{}), nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-out = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		statusOnly(t, browser.get(host, "/api/v1/dashboard", nil), http.StatusUnauthorized)
	})

	phase(t, "signing out ends the session when the provider has no logout endpoint", func(t *testing.T) {
		// Google does not advertise end_session_endpoint, so the documented fallback
		// applies: the local sign-out still happens and the browser returns to the
		// sign-in page rather than to the provider.
		browser := j.browser()
		host := j.adminHost()
		token := csrfFrom(t, bodyOf(t, browser.get(host, "/login", nil)))
		response := browser.form(host, "/auth/password", neturlValues(map[string]string{
			"csrf_token": token, "email": localAdminMail, "password": localAdminPass,
		}), nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-in = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		response = browser.form(host, "/auth/logout", neturlValues(map[string]string{}), nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-out = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		target := location(t, response)
		if target != "/login" && !strings.Contains(target, "accounts.google.com") {
			t.Errorf("sign-out redirect = %q, want the sign-in page or the provider", target)
		}
		if target == "/login" {
			// The session must really be gone.
			statusOnly(t, browser.get(host, "/api/v1/dashboard", nil), http.StatusUnauthorized)
		}
	})

	phase(t, "an oversized profile upload is refused", func(t *testing.T) {
		big := strings.Repeat("A", 5<<20)
		response := j.admin.json(http.MethodPut, host, "/api/v1/profile", map[string]string{"avatar": big})
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", response.StatusCode)
		}
		bodyOf(t, response)
	})
}
