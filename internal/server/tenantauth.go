package server

import (
	"context"
	"encoding/base64"
	"errors"
	"html"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/danyel/go-loose/web"
)

func (s *Server) tenantAuthHost(tenantSlug string) string {
	host := tenantSlug + "." + s.cfg.AuthDomain
	if parsed, err := url.Parse(s.cfg.BaseURL); err == nil && parsed.Port() != "" {
		host = net.JoinHostPort(host, parsed.Port())
	}
	return host
}

func (s *Server) tenantAuthURL(tenantSlug, requestURI string) string {
	base, _ := url.Parse(s.cfg.BaseURL)
	return base.Scheme + "://" + s.tenantAuthHost(tenantSlug) + requestURI
}

func (s *Server) validateLoginReturn(ctx context.Context, raw string) (string, error) {
	target, err := url.Parse(raw)
	if err != nil || !target.IsAbs() || target.Path != "/connect/authorize" || target.Fragment != "" || target.User != nil {
		return "", errors.New("invalid return URL")
	}
	base, err := url.Parse(s.cfg.BaseURL)
	if err != nil || target.Scheme != base.Scheme {
		return "", errors.New("invalid return scheme")
	}
	clientID, redirectURI := target.Query().Get("client_id"), target.Query().Get("redirect_uri")
	app, err := s.store.ValidateClientRedirect(ctx, clientID, redirectURI)
	if err != nil || !strings.EqualFold(target.Host, s.tenantAuthHost(app.TenantSlug)) {
		return "", errors.New("return URL does not match client tenant")
	}
	return target.String(), nil
}

func (s *Server) newLoginState(target string) (string, error) {
	nonce, err := s.sessions.NewState()
	if err != nil {
		return "", err
	}
	payload := nonce + "|" + base64.RawURLEncoding.EncodeToString([]byte(target))
	return s.sessions.SignedState(payload), nil
}

func (s *Server) loginTargetFromState(state string) (string, error) {
	payload, ok := s.sessions.VerifySigned(state)
	if !ok {
		return "", errors.New("invalid signed state")
	}
	parts := strings.SplitN(payload, "|", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", errors.New("invalid state payload")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("invalid state target")
	}
	target := string(decoded)
	if target == "/" {
		return target, nil
	}
	return s.validateLoginReturn(context.Background(), target)
}

func (s *Server) renderClientLogin(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	returnURL := r.URL.Query().Get("return")
	app, err := s.store.ClientByID(r.Context(), clientID)
	if err != nil || !strings.EqualFold(r.Host, s.tenantAuthHost(app.TenantSlug)) {
		http.NotFound(w, r)
		return
	}
	validatedReturn, err := s.validateLoginReturn(r.Context(), returnURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid client login request")
		return
	}
	content, err := web.Files.ReadFile("client-login.html")
	if err != nil {
		http.Error(w, "login page unavailable", http.StatusInternalServerError)
		return
	}
	loginURL := "/auth/start?return=" + url.QueryEscape(validatedReturn)
	csrfToken, err := s.loginCSRFToken(w)
	if err != nil {
		http.Error(w, "could not prepare login", http.StatusInternalServerError)
		return
	}
	page := strings.NewReplacer(
		"{{TENANT_NAME}}", html.EscapeString(app.TenantName),
		"{{APPLICATION_NAME}}", html.EscapeString(app.Name),
		"{{LOGIN_URL}}", html.EscapeString(loginURL),
		"{{RETURN_URL}}", html.EscapeString(validatedReturn),
		"{{CSRF_TOKEN}}", html.EscapeString(csrfToken),
		"{{LOCAL_STYLE}}", hiddenStyle(!s.cfg.LocalLogin),
		"{{SSO_STYLE}}", hiddenStyle(!s.hasOIDC()),
	).Replace(string(content))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func (s *Server) renderManagementLogin(w http.ResponseWriter, _ *http.Request) {
	content, err := web.Files.ReadFile("login.html")
	if err != nil {
		http.Error(w, "login page unavailable", http.StatusInternalServerError)
		return
	}
	csrfToken, err := s.loginCSRFToken(w)
	if err != nil {
		http.Error(w, "could not prepare login", http.StatusInternalServerError)
		return
	}
	page := strings.NewReplacer(
		"{{CSRF_TOKEN}}", html.EscapeString(csrfToken),
		"{{LOCAL_STYLE}}", hiddenStyle(!s.cfg.LocalLogin),
		"{{SSO_STYLE}}", hiddenStyle(!s.hasOIDC()),
	).Replace(string(content))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func (s *Server) loginCSRFToken(w http.ResponseWriter) (string, error) {
	state, err := s.sessions.NewState()
	if err != nil {
		return "", err
	}
	token := s.sessions.SignedState("login|" + state)
	http.SetCookie(w, &http.Cookie{
		Name: "go_loose_login_csrf", Value: token, Path: "/auth/password",
		HttpOnly: true, Secure: strings.HasPrefix(s.cfg.BaseURL, "https://"),
		SameSite: http.SameSiteStrictMode, MaxAge: 600,
	})
	return token, nil
}

func hiddenStyle(hidden bool) string {
	if hidden {
		return "display:none"
	}
	return ""
}
