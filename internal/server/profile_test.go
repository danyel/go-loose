package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/danyel/go-loose/internal/config"
	"github.com/danyel/go-loose/internal/role"
	"github.com/danyel/go-loose/internal/session"
	"github.com/danyel/go-loose/internal/store"
	"github.com/danyel/go-loose/web"
)

func profileTestServer() *Server {
	return &Server{cfg: config.Config{BaseURL: "https://auth.example.test"}}
}

func profileRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "https://auth.example.test/api/v1/profile", strings.NewReader(body))
	claims := session.Claims{UserID: "user-1", Management: true}
	return request.WithContext(context.WithValue(request.Context(), claimsKey, claims))
}

func TestAvatarURLIsAbsoluteAndOmittedWithoutKey(t *testing.T) {
	server := profileTestServer()
	if got := server.avatarURL(nil); got != "" {
		t.Fatalf("avatarURL(nil) = %q, want empty", got)
	}
	empty := ""
	if got := server.avatarURL(&empty); got != "" {
		t.Fatalf("avatarURL(empty) = %q, want empty", got)
	}
	key := "k"
	got := server.avatarURL(&key)
	if want := "https://auth.example.test/api/v1/avatars/k"; got != want {
		t.Fatalf("avatarURL() = %q, want %q", got, want)
	}
	parsed, err := url.Parse(got)
	if err != nil || parsed.Path != "/api/v1/avatars/k" {
		t.Fatalf("avatar url = %q, err = %v", got, err)
	}
}

// TestClientUserExposesRoleCapabilitiesAndPicture checks that the identity
// handed to a client application carries the capabilities the store resolved for
// the membership's role rather than anything the server infers.
func TestClientUserExposesRoleCapabilitiesAndPicture(t *testing.T) {
	server := profileTestServer()
	key := "avatar-key"
	payload := server.clientUser(store.ClientUser{
		ID: "user-1", Email: "operator@example.test", DisplayName: "Operator",
		TenantSlug: "nmbs", Application: "guess", Role: "operator",
		Permissions: []string{string(role.ManageKeys), string(role.EditProfile)},
		AvatarKey:   &key,
	})
	if payload.Role != "operator" {
		t.Fatalf("role = %q", payload.Role)
	}
	if !slices.Contains(payload.Permissions, string(role.ManageKeys)) {
		t.Fatalf("permissions = %v, want keys.manage", payload.Permissions)
	}
	if slices.Contains(payload.Permissions, string(role.ManageTenants)) {
		t.Fatalf("permissions = %v, must not grant tenants.manage", payload.Permissions)
	}
	if !strings.HasSuffix(payload.AvatarURL, "/api/v1/avatars/avatar-key") {
		t.Fatalf("avatar url = %q", payload.AvatarURL)
	}
}

// TestClientUserWithoutMembershipIsLeastPrivileged documents the pass-through: a
// user with no membership is reported with the permissions of the built-in User
// role, which the store resolves, so an empty capability set reaches clients
// rather than an error.
func TestClientUserWithoutMembershipIsLeastPrivileged(t *testing.T) {
	server := profileTestServer()
	payload := server.clientUser(store.ClientUser{Role: "user", Permissions: []string{string(role.EditProfile)}})
	if payload.AvatarURL != "" {
		t.Fatalf("avatar url = %q, want empty", payload.AvatarURL)
	}
	if !slices.Equal(payload.Permissions, []string{string(role.EditProfile)}) {
		t.Fatalf("permissions = %v, want only profile.edit", payload.Permissions)
	}
}

func TestAvatarRejectsMalformedKeyWithoutQueryingTheDatabase(t *testing.T) {
	server := profileTestServer()
	for _, key := range []string{"", "short", "../../etc/passwd", strings.Repeat("a", 44)} {
		request := httptest.NewRequest(http.MethodGet, "https://auth.example.test/api/v1/avatars/"+key, nil)
		request.SetPathValue("key", key)
		response := httptest.NewRecorder()
		server.avatar(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("avatar(%q) status = %d, want %d", key, response.Code, http.StatusNotFound)
		}
		if body := response.Body.String(); strings.Contains(body, "avatar") {
			t.Fatalf("avatar(%q) leaked internals: %s", key, body)
		}
	}
}

func TestUpdateProfileRejectsInvalidRequests(t *testing.T) {
	server := profileTestServer()
	picture := base64.StdEncoding.EncodeToString(tinyPNG(t))
	tests := []struct {
		name string
		body string
	}{
		{name: "unknown field", body: `{"display_name":"Ana","admin":true}`},
		{name: "two JSON objects", body: `{"display_name":"Ana"}{"display_name":"Bo"}`},
		{name: "blank display name", body: `{"display_name":"   "}`},
		{name: "oversized display name", body: `{"display_name":"` + strings.Repeat("a", maxDisplayName+1) + `"}`},
		{name: "picture and removal", body: `{"avatar":"` + picture + `","remove_avatar":true}`},
		{name: "picture is not base64", body: `{"avatar":"!!!not base64!!!"}`},
		{name: "picture is not an image", body: `{"avatar":"` + base64.StdEncoding.EncodeToString([]byte("<svg/>")) + `"}`},
		{name: "picture media type mismatch", body: `{"avatar":"data:image/gif;base64,` + picture + `"}`},
		{name: "nothing to update", body: `{}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.updateProfile(response, profileRequest(t, test.body))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (body %s)", response.Code, http.StatusBadRequest, response.Body)
			}
		})
	}
}

func TestUpdateProfileRejectsOversizedBody(t *testing.T) {
	server := profileTestServer()
	body := `{"avatar":"` + strings.Repeat("A", maxProfileBody) + `"}`
	response := httptest.NewRecorder()
	server.updateProfile(response, profileRequest(t, body))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestProfilePageIsEmbedded(t *testing.T) {
	content, err := web.Files.ReadFile("profile.html")
	if err != nil {
		t.Fatalf("profile.html must be embedded: %v", err)
	}
	for _, marker := range []string{"avatar-file", "profile-form", "/assets/profile.js"} {
		if !bytes.Contains(content, []byte(marker)) {
			t.Fatalf("profile.html is missing %q", marker)
		}
	}
}

func tinyPNG(t *testing.T) []byte {
	t.Helper()
	canvas := image.NewRGBA(image.Rect(0, 0, 2, 2))
	canvas.Set(0, 0, color.RGBA{R: 255, A: 255})
	buffer := &bytes.Buffer{}
	if err := png.Encode(buffer, canvas); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buffer.Bytes()
}
