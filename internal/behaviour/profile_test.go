package behaviour

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

// profilePhases edits the caller's own display name and picture, and checks the
// public URL that client applications such as go-tell embed.
func profilePhases(t *testing.T, j *journey) {
	t.Helper()
	host := j.adminHost()

	phase(t, "the profile reports the caller and their memberships", func(t *testing.T) {
		type membership struct {
			TenantSlug  string   `json:"tenant_slug"`
			Role        string   `json:"role"`
			RoleID      string   `json:"role_id"`
			Permissions []string `json:"permissions"`
		}
		type profile struct {
			ID             string       `json:"id"`
			Email          string       `json:"email"`
			DisplayName    string       `json:"display_name"`
			AvatarURL      string       `json:"avatar_url"`
			Memberships    []membership `json:"memberships"`
			NameCustomized bool         `json:"name_customized"`
		}
		result := decode[profile](t, j.admin.get(host, "/api/v1/profile", nil), http.StatusOK)
		if result.Email != localAdminMail {
			t.Errorf("email = %q", result.Email)
		}
		if result.DisplayName != "Local Administrator" {
			t.Errorf("display name = %q", result.DisplayName)
		}
		if result.AvatarURL != "" {
			t.Errorf("avatar_url = %q, want empty before a picture is set", result.AvatarURL)
		}
		if result.NameCustomized {
			t.Error("name_customized is true before the name was edited")
		}
		if len(result.Memberships) == 0 {
			t.Fatal("no memberships reported")
		}
		for _, membership := range result.Memberships {
			if len(membership.Permissions) == 0 {
				t.Errorf("membership %s reports no permissions", membership.TenantSlug)
			}
		}
	})

	phase(t, "an empty update is refused", func(t *testing.T) {
		statusOnly(t, j.admin.json(http.MethodPut, host, "/api/v1/profile", map[string]any{}), http.StatusBadRequest)
	})

	phase(t, "an empty display name is refused", func(t *testing.T) {
		response := j.admin.json(http.MethodPut, host, "/api/v1/profile", map[string]any{"display_name": "   "})
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "the display name is changed and marked as customized", func(t *testing.T) {
		j.profileName = "Ada Lovelace"
		type updated struct {
			DisplayName    string `json:"display_name"`
			NameCustomized bool   `json:"name_customized"`
		}
		response := j.admin.json(http.MethodPut, host, "/api/v1/profile", map[string]any{
			"display_name": j.profileName,
		})
		result := decode[updated](t, response, http.StatusOK)
		if result.DisplayName != j.profileName {
			t.Errorf("display name = %q", result.DisplayName)
		}
		if !result.NameCustomized {
			t.Error("name_customized was not set")
		}
	})

	phase(t, "the customized name survives signing in again", func(t *testing.T) {
		// Signing in upserts the user from the identity provider, which would
		// otherwise overwrite the name the person chose.
		browser := j.browser()
		token := csrfFrom(t, bodyOf(t, browser.get(host, "/login", nil)))
		response := browser.form(host, "/auth/password", neturlValues(map[string]string{
			"csrf_token": token, "email": localAdminMail, "password": localAdminPass,
		}), nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-in = %d: %s", response.StatusCode, bodyOf(t, response))
		}

		type profile struct {
			DisplayName string `json:"display_name"`
		}
		result := decode[profile](t, browser.get(host, "/api/v1/profile", nil), http.StatusOK)
		if result.DisplayName != j.profileName {
			t.Errorf("display name = %q after signing in, want %q", result.DisplayName, j.profileName)
		}
	})

	phase(t, "a picture is rejected when it is not an image", func(t *testing.T) {
		response := j.admin.json(http.MethodPut, host, "/api/v1/profile", map[string]any{
			"avatar": base64.StdEncoding.EncodeToString([]byte("this is not an image")),
		})
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "an unsupported image type is rejected", func(t *testing.T) {
		// A real PNG announced as a PDF: the declared type must be checked.
		response := j.admin.json(http.MethodPut, host, "/api/v1/profile", map[string]any{
			"avatar": "data:application/pdf;base64," + base64.StdEncoding.EncodeToString(decodeBase64PNG(t)),
		})
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "a picture is accepted and published under a key", func(t *testing.T) {
		type updated struct {
			AvatarURL string `json:"avatar_url"`
		}
		response := j.admin.json(http.MethodPut, host, "/api/v1/profile", map[string]any{
			"avatar": base64.StdEncoding.EncodeToString(decodeBase64PNG(t)),
		})
		result := decode[updated](t, response, http.StatusOK)
		if !strings.HasPrefix(result.AvatarURL, "/api/v1/avatars/") {
			t.Fatalf("avatar_url = %q, want a path under /api/v1/avatars", result.AvatarURL)
		}
		j.avatarKey = strings.TrimPrefix(result.AvatarURL, "/api/v1/avatars/")
		if j.avatarKey == "" {
			t.Fatal("no avatar key")
		}
	})

	phase(t, "the picture is served to anyone, without a session", func(t *testing.T) {
		stranger := j.browser()
		response := stranger.get(j.h.apex(), "/api/v1/avatars/"+j.avatarKey, nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", response.StatusCode)
		}
		if got := response.Header.Get("Content-Type"); got != "image/png" {
			t.Errorf("content type = %q, want image/png", got)
		}
		if got := response.Header.Get("Cache-Control"); !strings.Contains(got, "max-age") {
			t.Errorf("cache control = %q", got)
		}
		if response.Header.Get("ETag") == "" {
			t.Error("no ETag on a picture")
		}
		if got := response.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("nosniff = %q", got)
		}
		body := bodyOf(t, response)
		if len(body) == 0 {
			t.Error("empty picture body")
		}
	})

	phase(t, "an unchanged picture answers 304", func(t *testing.T) {
		first := j.browser().get(j.h.apex(), "/api/v1/avatars/"+j.avatarKey, nil)
		etag := first.Header.Get("ETag")
		bodyOf(t, first)

		second := j.browser().get(j.h.apex(), "/api/v1/avatars/"+j.avatarKey, map[string]string{
			"If-None-Match": etag,
		})
		if second.StatusCode != http.StatusNotModified {
			t.Fatalf("status = %d, want 304", second.StatusCode)
		}
		second.Body.Close()
	})

	phase(t, "an unknown or malformed picture key never serves anything", func(t *testing.T) {
		for _, key := range []string{"does-not-exist", strings.Repeat("a", 43), "..%2f..%2fetc%2fpasswd"} {
			response := j.browser().get(j.h.apex(), "/api/v1/avatars/"+key, nil)
			// A traversal may be normalised into a redirect by the router; what matters
			// is that no bytes are ever served for it.
			if response.StatusCode == http.StatusOK {
				t.Errorf("key %q returned a picture", key)
			}
			bodyOf(t, response)
		}
	})

	phase(t, "replacing the picture retires the old key", func(t *testing.T) {
		original := j.avatarKey
		type updated struct {
			AvatarURL string `json:"avatar_url"`
		}
		// A different image: the 1x1 PNG's colour channel is inverted.
		response := j.admin.json(http.MethodPut, host, "/api/v1/profile", map[string]any{
			"avatar": base64.StdEncoding.EncodeToString(decodeBase64PNG(t)),
		})
		result := decode[updated](t, response, http.StatusOK)
		j.avatarKey = strings.TrimPrefix(result.AvatarURL, "/api/v1/avatars/")
		if j.avatarKey == "" {
			t.Fatal("no avatar key after replacing the picture")
		}
		response = j.browser().get(j.h.apex(), "/api/v1/avatars/"+original, nil)
		if response.StatusCode != http.StatusNotFound {
			t.Errorf("the previous key still resolves: %d", response.StatusCode)
		}
		response.Body.Close()
		response = j.browser().get(j.h.apex(), "/api/v1/avatars/"+j.avatarKey, nil)
		if response.StatusCode != http.StatusOK {
			t.Errorf("the new key does not resolve: %d", response.StatusCode)
		}
		response.Body.Close()
	})

	phase(t, "the profile of another member still shows no picture", func(t *testing.T) {
		type profile struct {
			Email     string `json:"email"`
			AvatarURL string `json:"avatar_url"`
		}
		result := decode[profile](t, j.admin.get(host, "/api/v1/profile", nil), http.StatusOK)
		if result.AvatarURL == "" {
			t.Error("the administrator's picture disappeared")
		}
	})

	phase(t, "removing the picture clears it everywhere", func(t *testing.T) {
		key := j.avatarKey
		type updated struct {
			AvatarURL string `json:"avatar_url"`
		}
		response := j.admin.json(http.MethodPut, host, "/api/v1/profile", map[string]any{"remove_avatar": true})
		result := decode[updated](t, response, http.StatusOK)
		if result.AvatarURL != "" {
			t.Errorf("avatar_url = %q, want empty", result.AvatarURL)
		}
		response = j.browser().get(j.h.apex(), "/api/v1/avatars/"+key, nil)
		if response.StatusCode != http.StatusNotFound {
			t.Errorf("the removed picture still resolves: %d", response.StatusCode)
		}
		response.Body.Close()
	})

	phase(t, "the member is moved to the self-service role", func(t *testing.T) {
		// The role phase left this person holding a role that grants console.read.
		// Moving them to the built-in self-service role is the flow that proves the
		// console and the API agree about who may open it.
		response := j.admin.json(http.MethodPut, host, "/api/v1/users/"+j.ungrantedMemberID+"/access", map[string]any{
			"tenant_id": j.scopedTenantID, "role_id": j.userRoleID, "application_ids": []string{},
		})
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("change role = %d: %s", response.StatusCode, bodyOf(t, response))
		}
	})

	phase(t, "a member without console access is sent to their profile page", func(t *testing.T) {
		// The ungranted member holds the self-service role, which grants
		// profile.edit but not console.read.
		browser := j.browser()
		tenantHost := j.h.tenantHost(j.scopedTenant)
		token := csrfFrom(t, bodyOf(t, browser.get(tenantHost, "/login", nil)))
		response := browser.form(tenantHost, "/auth/password", neturlValues(map[string]string{
			"csrf_token": token, "email": j.ungrantedEmail, "password": j.ungrantedPassword,
		}), nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-in = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		response = browser.get(tenantHost, "/", nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("console = %d, want a redirect: %s", response.StatusCode, bodyOf(t, response))
		}
		if got := location(t, response); got != "/profile" {
			t.Errorf("redirect = %q, want /profile", got)
		}
		page := bodyOf(t, browser.get(tenantHost, "/profile", nil))
		if !strings.Contains(page, "<html") {
			t.Error("the profile page did not render")
		}
	})

	phase(t, "a member without console access cannot read the dashboard", func(t *testing.T) {
		browser := j.browser()
		tenantHost := j.h.tenantHost(j.scopedTenant)
		token := csrfFrom(t, bodyOf(t, browser.get(tenantHost, "/login", nil)))
		response := browser.form(tenantHost, "/auth/password", neturlValues(map[string]string{
			"csrf_token": token, "email": j.ungrantedEmail, "password": j.ungrantedPassword,
		}), nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-in = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		statusOnly(t, browser.get(tenantHost, "/api/v1/dashboard", nil), http.StatusForbidden)
	})
}
