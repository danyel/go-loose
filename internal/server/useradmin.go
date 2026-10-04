package server

import (
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/danyel/go-loose/internal/key"
	"github.com/danyel/go-loose/internal/password"
	"github.com/danyel/go-loose/internal/role"
)

// assignableRole validates a role that an administrator may hand to an existing
// member. Any known role qualifies, including owner, so that ownership can move
// between accounts deliberately.
func assignableRole(value string) (string, bool) {
	parsed, ok := role.Parse(value)
	return string(parsed), ok
}

// invitableRole validates a role for a new invitation. Ownership is established
// by creating or claiming a tenant, so it is never granted here.
func invitableRole(value string) (string, bool) {
	for _, item := range role.Grantable() {
		if string(item) == value {
			return value, true
		}
	}
	return "", false
}

func (s *Server) configureClient(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if len(request.RedirectURIs) == 0 {
		writeError(w, http.StatusBadRequest, "at least one redirect URI is required")
		return
	}
	seen := make(map[string]bool)
	for index, raw := range request.RedirectURIs {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Fragment != "" || parsed.User != nil {
			writeError(w, http.StatusBadRequest, "redirect URIs must be absolute URLs without fragments or credentials")
			return
		}
		localHTTP := (s.cfg.DevLogin || s.cfg.LocalLogin) && parsed.Scheme == "http" &&
			(parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1")
		if parsed.Scheme != "https" && !localHTTP {
			writeError(w, http.StatusBadRequest, "redirect URIs require HTTPS except localhost in development")
			return
		}
		request.RedirectURIs[index] = parsed.String()
		if seen[parsed.String()] {
			writeError(w, http.StatusBadRequest, "redirect URIs must be unique")
			return
		}
		seen[parsed.String()] = true
	}
	secret, _, hash, err := key.GenerateToken("glc_secret_")
	if err != nil {
		s.internalError(w, "generate client secret", err)
		return
	}
	app, err := s.store.ConfigureClient(r.Context(), claimsFrom(r).UserID, r.PathValue("id"), request.RedirectURIs, hash)
	if err != nil {
		s.handleStoreError(w, "configure client login", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"application": app, "client_secret": secret})
}

func (s *Server) inviteUser(w http.ResponseWriter, r *http.Request) {
	var request struct {
		TenantID    string `json:"tenant_id"`
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
		Password    string `json:"password"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	address, err := mail.ParseAddress(strings.TrimSpace(request.Email))
	if err != nil || address.Address != request.Email {
		writeError(w, http.StatusBadRequest, "a valid plain email address is required")
		return
	}
	request.Email = strings.ToLower(address.Address)
	request.DisplayName = strings.TrimSpace(request.DisplayName)
	if request.DisplayName == "" {
		request.DisplayName = request.Email
	}
	invitedRole, ok := invitableRole(request.Role)
	if !ok {
		writeError(w, http.StatusBadRequest, "role must be one of "+strings.Join(role.GrantableValues(), ", "))
		return
	}
	passwordHash, err := password.Hash(request.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := s.store.InviteUser(r.Context(), claimsFrom(r).UserID, request.TenantID, request.Email, request.DisplayName, invitedRole, passwordHash)
	if err != nil {
		s.handleStoreError(w, "invite user", err)
		return
	}
	user.AvatarURL = s.avatarURL(user.AvatarKey)
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) setUserAccess(w http.ResponseWriter, r *http.Request) {
	var request struct {
		TenantID       string   `json:"tenant_id"`
		Role           string   `json:"role"`
		ApplicationIDs []string `json:"application_ids"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	membershipRole, ok := assignableRole(request.Role)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid role")
		return
	}
	if err := s.store.SetUserAccess(r.Context(), claimsFrom(r).UserID, request.TenantID, r.PathValue("id"), membershipRole, request.ApplicationIDs); err != nil {
		s.handleStoreError(w, "update user access", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) approveUser(w http.ResponseWriter, r *http.Request) {
	var request struct {
		TenantID       string   `json:"tenant_id"`
		Role           string   `json:"role"`
		ApplicationIDs []string `json:"application_ids"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	membershipRole, ok := assignableRole(request.Role)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid role")
		return
	}
	if err := s.store.ApprovePendingUser(
		r.Context(), claimsFrom(r).UserID, request.TenantID, r.PathValue("id"),
		membershipRole, request.ApplicationIDs,
	); err != nil {
		s.handleStoreError(w, "approve pending user", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
