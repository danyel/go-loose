package behaviour

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// clientPhases walks the whole hosted-login dance a tenant application performs:
// it configures a client, sends a member to the provider, comes back with a code,
// exchanges it for a bearer token, reads the identity, and signs out again.
func clientLoginPhases(t *testing.T, j *journey) {
	t.Helper()
	host := j.adminHost()
	redirectURI := "https://app.behaviour.test/auth/callback"

	phase(t, "a redirect URI that is not HTTPS is refused", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, host,
			"/api/v1/applications/"+j.applicationID+"/client-config", map[string]any{
				"redirect_uris": []string{"http://app.behaviour.test/callback"},
			})
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "a redirect URI carrying a fragment is refused", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, host,
			"/api/v1/applications/"+j.applicationID+"/client-config", map[string]any{
				"redirect_uris": []string{"https://app.behaviour.test/callback#token"},
			})
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "duplicate redirect URIs are refused", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, host,
			"/api/v1/applications/"+j.applicationID+"/client-config", map[string]any{
				"redirect_uris": []string{redirectURI, redirectURI},
			})
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "client login is configured and the application becomes ready", func(t *testing.T) {
		type configured struct {
			Application struct {
				ID           string   `json:"id"`
				ClientID     string   `json:"client_id"`
				RedirectURIs []string `json:"redirect_uris"`
				ClientReady  bool     `json:"client_ready"`
			} `json:"application"`
			ClientSecret string `json:"client_secret"`
		}
		response := j.admin.json(http.MethodPost, host,
			"/api/v1/applications/"+j.applicationID+"/client-config", map[string]any{
				"redirect_uris": []string{redirectURI},
			})
		result := decode[configured](t, response, http.StatusOK)
		if result.ClientSecret == "" {
			t.Fatal("no client secret returned")
		}
		if result.Application.ClientID == "" {
			t.Error("no client id assigned")
		}
		if !result.Application.ClientReady {
			t.Error("the application is not reported as ready for client login")
		}
		if len(result.Application.RedirectURIs) != 1 {
			t.Errorf("redirect URIs = %v", result.Application.RedirectURIs)
		}
		j.clientID, j.clientSecret = result.Application.ClientID, result.ClientSecret
	})

	phase(t, "an unknown client is refused at the authorize endpoint", func(t *testing.T) {
		browser := j.browser()
		response := browser.get(host, "/connect/authorize?response_type=code&client_id=glc_unknown"+
			"&redirect_uri="+url.QueryEscape(redirectURI)+"&state=xyz", nil)
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "incomplete authorize parameters are refused", func(t *testing.T) {
		browser := j.browser()
		for _, query := range []string{
			"client_id=" + j.clientID,
			"response_type=token&client_id=" + j.clientID + "&state=s",
			"response_type=code&client_id=" + j.clientID + "&redirect_uri=" + url.QueryEscape(redirectURI),
		} {
			response := browser.get(host, "/connect/authorize?"+query, nil)
			if response.StatusCode != http.StatusBadRequest {
				t.Errorf("authorize with %q = %d, want 400", query, response.StatusCode)
			}
			response.Body.Close()
		}
	})

	phase(t, "an apex request is redirected onto the tenant hostname", func(t *testing.T) {
		browser := j.browser()
		query := "response_type=code&client_id=" + j.clientID +
			"&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=tenant-host"
		response := browser.get(j.h.apex(), "/connect/authorize?"+query, nil)
		if response.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("status = %d, want 307: %s", response.StatusCode, bodyOf(t, response))
		}
		if !strings.Contains(location(t, response), j.h.tenantHost(j.scopedTenant)) {
			t.Errorf("redirect = %q, want the tenant host", location(t, response))
		}
	})

	phase(t, "a signed-out visitor is sent to the tenant sign-in page", func(t *testing.T) {
		browser := j.browser()
		tenantHost := j.h.tenantHost(j.scopedTenant)
		query := "response_type=code&client_id=" + j.clientID +
			"&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=signin"
		response := browser.get(tenantHost, "/connect/authorize?"+query, nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303: %s", response.StatusCode, bodyOf(t, response))
		}
		target := location(t, response)
		if !strings.Contains(target, "/client/login") {
			t.Fatalf("redirect = %q, want the client sign-in page", target)
		}
		page := bodyOf(t, browser.get(tenantHost, target, nil))
		if !strings.Contains(page, "csrf_token") {
			t.Errorf("the sign-in page has no form: %.200s", page)
		}
	})

	phase(t, "a member without an application grant is refused", func(t *testing.T) {
		// This person is a member of the tenant but was never granted the
		// application, which is the distinction the endpoint has to enforce.
		browser := j.browser()
		tenantHost := j.h.tenantHost(j.scopedTenant)
		query := "response_type=code&client_id=" + j.clientID +
			"&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=grant"
		response := browser.get(tenantHost, "/connect/authorize?"+query, nil)
		target := location(t, response)
		token := csrfFrom(t, bodyOf(t, browser.get(tenantHost, target, nil)))
		response = browser.form(tenantHost, "/auth/password", neturlValues(map[string]string{
			"csrf_token": token, "email": j.ungrantedEmail, "password": j.ungrantedPassword, "return": returnParam(t, target),
		}), nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-in = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		response = browser.get(tenantHost, "/connect/authorize?"+query, nil)
		statusOnly(t, response, http.StatusForbidden)
	})

	phase(t, "a granted member completes the flow and receives a session token", func(t *testing.T) {
		browser := j.browser()
		tenantHost := j.h.tenantHost(j.scopedTenant)
		query := "response_type=code&client_id=" + j.clientID +
			"&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=happy"
		response := browser.get(tenantHost, "/connect/authorize?"+query, nil)
		target := location(t, response)
		token := csrfFrom(t, bodyOf(t, browser.get(tenantHost, target, nil)))
		response = browser.form(tenantHost, "/auth/password", neturlValues(map[string]string{
			"csrf_token": token, "email": j.memberEmail, "password": j.memberPassword, "return": returnParam(t, target),
		}), nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-in = %d: %s", response.StatusCode, bodyOf(t, response))
		}

		// Back to the authorize endpoint, now with a session: a code comes back.
		response = browser.get(tenantHost, "/connect/authorize?"+query, nil)
		if response.StatusCode != http.StatusFound {
			t.Fatalf("authorize = %d, want 302: %s", response.StatusCode, bodyOf(t, response))
		}
		callback, err := url.Parse(location(t, response))
		if err != nil {
			t.Fatalf("parse callback: %v", err)
		}
		if callback.Host != "app.behaviour.test" {
			t.Errorf("callback host = %q", callback.Host)
		}
		if callback.Query().Get("state") != "happy" {
			t.Errorf("state = %q, want happy", callback.Query().Get("state"))
		}
		code := callback.Query().Get("code")
		if code == "" {
			t.Fatal("no authorization code issued")
		}

		// The application exchanges the code for a token using HTTP Basic auth.
		type tokenResponse struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			User        struct {
				ID          string   `json:"id"`
				Email       string   `json:"email"`
				Role        string   `json:"role"`
				Permissions []string `json:"permissions"`
				TenantSlug  string   `json:"tenant_slug"`
				Application string   `json:"application"`
			} `json:"user"`
		}
		exchange := j.browser().request(http.MethodPost, j.h.apex(), "/connect/token",
			strings.NewReader(url.Values{
				"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
			}.Encode()), map[string]string{
				"Content-Type":  "application/x-www-form-urlencoded",
				"Authorization": "Basic " + basicAuth(j.clientID, j.clientSecret),
			})
		granted := decode[tokenResponse](t, exchange, http.StatusOK)
		if granted.AccessToken == "" {
			t.Fatal("no access token returned")
		}
		if granted.TokenType != "Bearer" {
			t.Errorf("token_type = %q", granted.TokenType)
		}
		if granted.ExpiresIn <= 0 {
			t.Errorf("expires_in = %d", granted.ExpiresIn)
		}
		if granted.User.Email != j.memberEmail {
			t.Errorf("user email = %q, want %s", granted.User.Email, j.memberEmail)
		}
		if granted.User.TenantSlug != j.scopedTenant {
			t.Errorf("tenant = %q, want %s", granted.User.TenantSlug, j.scopedTenant)
		}
		if granted.User.Role == "" || len(granted.User.Permissions) == 0 {
			t.Errorf("the token payload carries no role or permissions: %+v", granted.User)
		}
		j.accessToken = granted.AccessToken

		// The code is single use.
		replay := j.browser().request(http.MethodPost, j.h.apex(), "/connect/token",
			strings.NewReader(url.Values{
				"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
			}.Encode()), map[string]string{
				"Content-Type":  "application/x-www-form-urlencoded",
				"Authorization": "Basic " + basicAuth(j.clientID, j.clientSecret),
			})
		statusOnly(t, replay, http.StatusUnauthorized)
	})

	phase(t, "the token identifies the user at the userinfo endpoint", func(t *testing.T) {
		type identity struct {
			ID          string   `json:"id"`
			Email       string   `json:"email"`
			DisplayName string   `json:"display_name"`
			Role        string   `json:"role"`
			Permissions []string `json:"permissions"`
			Application string   `json:"application"`
		}
		response := j.browser().request(http.MethodGet, j.h.apex(), "/connect/userinfo", nil,
			map[string]string{"Authorization": "Bearer " + j.accessToken})
		user := decode[identity](t, response, http.StatusOK)
		if user.Email != j.memberEmail {
			t.Errorf("email = %q", user.Email)
		}
		if user.DisplayName == "" {
			t.Error("no display name")
		}
		if user.Application != "behaviour-app" {
			t.Errorf("application = %q", user.Application)
		}
	})

	phase(t, "a wrong client secret cannot exchange a code", func(t *testing.T) {
		response := j.browser().request(http.MethodPost, j.h.apex(), "/connect/token",
			strings.NewReader(url.Values{
				"grant_type": {"authorization_code"}, "code": {"glc_code_" + strings.Repeat("Q", 40)},
				"redirect_uri": {redirectURI},
			}.Encode()), map[string]string{
				"Content-Type":  "application/x-www-form-urlencoded",
				"Authorization": "Basic " + basicAuth(j.clientID, "glc_wrong_secret_value"),
			})
		statusOnly(t, response, http.StatusUnauthorized)
	})

	phase(t, "a token without basic authentication is refused", func(t *testing.T) {
		response := j.browser().request(http.MethodPost, j.h.apex(), "/connect/token",
			strings.NewReader("grant_type=authorization_code"), map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			})
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", response.StatusCode)
		}
		response.Body.Close()
		if response.Header.Get("WWW-Authenticate") == "" {
			t.Error("no WWW-Authenticate challenge was sent")
		}
	})

	phase(t, "userinfo refuses a request without a bearer token", func(t *testing.T) {
		statusOnly(t, j.browser().get(j.h.apex(), "/connect/userinfo", nil), http.StatusUnauthorized)
	})

	phase(t, "userinfo refuses a made-up token", func(t *testing.T) {
		response := j.browser().request(http.MethodGet, j.h.apex(), "/connect/userinfo", nil,
			map[string]string{"Authorization": "Bearer glc_session_" + strings.Repeat("Z", 43)})
		statusOnly(t, response, http.StatusUnauthorized)
	})

	phase(t, "signing out of the client invalidates the token at once", func(t *testing.T) {
		response := j.browser().request(http.MethodPost, j.h.apex(), "/connect/logout", nil,
			map[string]string{"Authorization": "Bearer " + j.accessToken})
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("logout = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		response.Body.Close()
		response = j.browser().request(http.MethodGet, j.h.apex(), "/connect/userinfo", nil,
			map[string]string{"Authorization": "Bearer " + j.accessToken})
		statusOnly(t, response, http.StatusUnauthorized)
	})
}

func basicAuth(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
}

// returnParam extracts the authorize URL that the sign-in page will return to,
// which is carried in the sign-in page's own query string.
func returnParam(t *testing.T, signInURL string) string {
	t.Helper()
	parsed, err := url.Parse(signInURL)
	if err != nil {
		t.Fatalf("parse sign-in URL %q: %v", signInURL, err)
	}
	value := parsed.Query().Get("return")
	if value == "" {
		t.Fatalf("the sign-in URL carries no return target: %q", signInURL)
	}
	return value
}

// establishClientSession runs the whole hosted-login dance and returns the bearer
// token, so a phase can assert on the token's lifetime rather than on the flow.
func establishClientSession(t *testing.T, j *journey, state string) string {
	t.Helper()
	browser := j.browser()
	tenantHost := j.h.tenantHost(j.scopedTenant)
	redirectURI := "https://app.behaviour.test/auth/callback"
	query := "response_type=code&client_id=" + j.clientID +
		"&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=" + state

	response := browser.get(tenantHost, "/connect/authorize?"+query, nil)
	signIn := location(t, response)
	token := csrfFrom(t, bodyOf(t, browser.get(tenantHost, signIn, nil)))
	response = browser.form(tenantHost, "/auth/password", neturlValues(map[string]string{
		"csrf_token": token, "email": j.memberEmail, "password": j.memberPassword,
		"return": returnParam(t, signIn),
	}), nil)
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign-in = %d: %s", response.StatusCode, bodyOf(t, response))
	}

	response = browser.get(tenantHost, "/connect/authorize?"+query, nil)
	if response.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d: %s", response.StatusCode, bodyOf(t, response))
	}
	callback, err := url.Parse(location(t, response))
	if err != nil {
		t.Fatalf("parse callback: %v", err)
	}

	type tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	exchange := j.browser().request(http.MethodPost, j.h.apex(), "/connect/token",
		strings.NewReader(url.Values{
			"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")},
			"redirect_uri": {redirectURI},
		}.Encode()), map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": "Basic " + basicAuth(j.clientID, j.clientSecret),
		})
	return decode[tokenResponse](t, exchange, http.StatusOK).AccessToken
}
