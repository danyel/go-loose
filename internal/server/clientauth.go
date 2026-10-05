package server

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danyel/go-loose/internal/key"
	"github.com/danyel/go-loose/internal/store"
)

// clientUserResponse is the identity payload handed to client applications. It
// carries the tenant role and its capabilities so that an application such as
// go-tell can gate features, plus an absolute avatar_url it can render directly.
type clientUserResponse struct {
	ID            string   `json:"id"`
	Email         string   `json:"email"`
	DisplayName   string   `json:"display_name"`
	AvatarURL     string   `json:"avatar_url"`
	TenantID      string   `json:"tenant_id"`
	TenantSlug    string   `json:"tenant_slug"`
	ApplicationID string   `json:"application_id"`
	Application   string   `json:"application"`
	Role          string   `json:"role"`
	Permissions   []string `json:"permissions"`
}

func (s *Server) clientUser(r *http.Request, user store.ClientUser) clientUserResponse {
	return clientUserResponse{
		ID: user.ID, Email: user.Email, DisplayName: user.DisplayName,
		AvatarURL: s.avatarURL(r, user.AvatarKey), TenantID: user.TenantID,
		TenantSlug: user.TenantSlug, ApplicationID: user.ApplicationID, Application: user.Application,
		Role: user.Role, Permissions: user.Permissions,
	}
}

func (s *Server) clientAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientID, redirectURI, state := query.Get("client_id"), query.Get("redirect_uri"), query.Get("state")
	if query.Get("response_type") != "code" || clientID == "" || redirectURI == "" || state == "" {
		writeError(w, http.StatusBadRequest, "response_type=code, client_id, redirect_uri, and state are required")
		return
	}
	app, err := s.store.ValidateClientRedirect(r.Context(), clientID, redirectURI)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "unknown client or redirect URI")
			return
		}
		s.internalError(w, "validate client redirect", err)
		return
	}
	if !strings.EqualFold(r.Host, s.tenantAuthHost(app.TenantSlug)) {
		http.Redirect(w, r, s.tenantAuthURL(app.TenantSlug, r.URL.RequestURI()), http.StatusTemporaryRedirect)
		return
	}
	claims, err := s.sessions.Get(r)
	if err != nil {
		returnURL := s.tenantAuthURL(app.TenantSlug, r.URL.RequestURI())
		loginQuery := url.Values{"client_id": {clientID}, "return": {returnURL}}
		http.Redirect(w, r, "/client/login?"+loginQuery.Encode(), http.StatusSeeOther)
		return
	}
	app, err = s.store.ClientForAuthorization(r.Context(), clientID, redirectURI, claims.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusForbidden, "your account does not have access to this application")
			return
		}
		s.internalError(w, "authorize client user", err)
		return
	}
	code, _, codeHash, err := key.GenerateToken("glc_code_")
	if err != nil {
		s.internalError(w, "generate authorization code", err)
		return
	}
	if err := s.store.CreateAuthorizationCode(r.Context(), app.ID, claims.UserID, redirectURI, codeHash); err != nil {
		s.internalError(w, "store authorization code", err)
		return
	}
	target, _ := url.Parse(redirectURI)
	values := target.Query()
	values.Set("code", code)
	values.Set("state", state)
	target.RawQuery = values.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *Server) clientToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid token request")
		return
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Go Loose token endpoint"`)
		writeError(w, http.StatusUnauthorized, "HTTP Basic client authentication required")
		return
	}
	code, redirectURI := r.Form.Get("code"), r.Form.Get("redirect_uri")
	if r.Form.Get("grant_type") != "authorization_code" || clientID == "" || clientSecret == "" || code == "" || redirectURI == "" {
		writeError(w, http.StatusBadRequest, "authorization_code grant parameters are required")
		return
	}
	token, _, tokenHash, err := key.GenerateToken("glc_session_")
	if err != nil {
		s.internalError(w, "generate client session", err)
		return
	}
	user, expiresAt, err := s.store.ExchangeAuthorizationCode(
		r.Context(), clientID, redirectURI, key.Hash(clientSecret), key.Hash(code), tokenHash,
	)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid or expired authorization code")
			return
		}
		s.internalError(w, "exchange authorization code", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token, "token_type": "Bearer",
		"expires_in": int(time.Until(expiresAt).Seconds()), "user": s.clientUser(r, user),
	})
}

func (s *Server) clientUserInfo(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "Bearer token required")
		return
	}
	user, err := s.store.ClientUserByToken(r.Context(), key.Hash(token))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "session is invalid or expired")
			return
		}
		s.internalError(w, "load client user", err)
		return
	}
	writeJSON(w, http.StatusOK, s.clientUser(r, user))
}

func (s *Server) clientLogout(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "Bearer token required")
		return
	}
	if err := s.store.RevokeClientSession(r.Context(), key.Hash(token)); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, "revoke client session", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
}
