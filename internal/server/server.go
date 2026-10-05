package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/danyel/go-loose/internal/config"
	"github.com/danyel/go-loose/internal/contract"
	"github.com/danyel/go-loose/internal/key"
	"github.com/danyel/go-loose/internal/secretbox"
	"github.com/danyel/go-loose/internal/session"
	"github.com/danyel/go-loose/internal/store"
	"github.com/danyel/go-loose/web"
	"golang.org/x/oauth2"
)

type Server struct {
	cfg      config.Config
	store    *store.Store
	db       *sql.DB
	sessions *session.Manager
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	// endSession is the identity provider's logout endpoint, empty when the
	// provider does not advertise one. It is what lets a sign-out here also end
	// the provider session the other applications in the family share.
	endSession string
	authMu     sync.RWMutex
	installed  atomic.Bool
	httpClient *http.Client
	logger     *slog.Logger
	loginGuard *loginGuard
}

type contextKey string

const claimsKey contextKey = "claims"

func New(ctx context.Context, cfg config.Config, db *sql.DB, logger *slog.Logger) (*Server, error) {
	server := &Server{
		cfg: cfg, store: store.New(db), db: db, logger: logger,
		sessions:   session.New(cfg.SessionSecret, strings.HasPrefix(cfg.BaseURL, "https://")),
		loginGuard: newLoginGuard(),
	}
	server.httpClient = &http.Client{
		Timeout: cfg.HTTPTimeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many contract source redirects")
			}
			_, err := contract.ValidateSourceURL(request.URL.String(), cfg.AllowPrivateContractURL)
			return err
		},
	}
	installation, err := server.store.Installation(ctx)
	if err == nil {
		secret, decryptErr := secretbox.Decrypt(cfg.SessionSecret, installation.OIDCSecretCiphertext)
		if decryptErr != nil {
			return nil, fmt.Errorf("decrypt installed OIDC secret: %w", decryptErr)
		}
		if err := server.configureOIDC(ctx, installation.OIDCIssuer, installation.OIDCClientID, secret, installation.OIDCRedirectURL); err != nil {
			return nil, err
		}
		server.installed.Store(true)
		if err := server.ensureLocalAdministrator(ctx); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("load installation: %w", err)
	} else if cfg.OIDCIssuer != "" && cfg.OIDCClientID != "" && cfg.OIDCClientSecret != "" {
		if err := server.configureOIDC(ctx, cfg.OIDCIssuer, cfg.OIDCClientID, cfg.OIDCClientSecret, cfg.OIDCRedirectURL); err != nil {
			return nil, err
		}
		server.installed.Store(true)
		if err := server.ensureLocalAdministrator(ctx); err != nil {
			return nil, err
		}
	} else if cfg.LocalLogin && cfg.LocalAdminPassword != "" {
		server.installed.Store(true)
		if err := server.ensureLocalAdministrator(ctx); err != nil {
			return nil, err
		}
	}
	return server, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /install", s.installPage)
	mux.HandleFunc("POST /install", s.install)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("GET /auth/start", s.authStart)
	mux.HandleFunc("GET /auth/callback", s.authCallback)
	mux.HandleFunc("GET /auth/dev", s.authDev)
	mux.HandleFunc("POST /auth/logout", s.authLogout)
	mux.HandleFunc("POST /auth/password", s.passwordLogin)
	mux.HandleFunc("GET /assets/{name}", s.asset)
	mux.HandleFunc("GET /api/v1/avatars/{key}", s.avatar)
	mux.HandleFunc("POST /api/v1/authorize", s.authorize)
	mux.HandleFunc("GET /connect/authorize", s.clientAuthorize)
	mux.HandleFunc("POST /connect/token", s.clientToken)
	mux.HandleFunc("GET /connect/userinfo", s.clientUserInfo)
	mux.HandleFunc("POST /connect/logout", s.clientLogout)
	mux.HandleFunc("GET /client/login", s.clientLoginPage)

	// {$} matches only "/". The unanchored pattern "GET /" is a catch-all, so a
	// browser favicon request would redirect to /install and rotate its CSRF cookie.
	mux.Handle("GET /{$}", s.requireSession(http.HandlerFunc(s.index)))
	mux.Handle("GET /profile", s.requireSession(http.HandlerFunc(s.profilePage)))
	mux.Handle("GET /roles", s.requireSession(http.HandlerFunc(s.rolesPage)))
	mux.Handle("GET /api/v1/profile", s.requireSession(http.HandlerFunc(s.profile)))
	mux.Handle("PUT /api/v1/profile", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.updateProfile))))
	mux.Handle("GET /docs", s.requireSession(http.HandlerFunc(s.docs)))
	mux.Handle("GET /openapi.json", s.requireSession(http.HandlerFunc(s.openapi)))
	mux.Handle("GET /api/v1/dashboard", s.requireSession(http.HandlerFunc(s.dashboard)))
	mux.Handle("POST /api/v1/tenants", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.createTenant))))
	mux.Handle("POST /api/v1/applications", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.createApplication))))
	mux.Handle("POST /api/v1/keys", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.createKey))))
	mux.Handle("POST /api/v1/keys/{id}/revoke", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.revokeKey))))
	mux.Handle("POST /api/v1/contracts", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.createContract))))
	mux.Handle("POST /api/v1/applications/{id}/client-config", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.configureClient))))
	mux.Handle("POST /api/v1/users", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.inviteUser))))
	mux.Handle("PUT /api/v1/users/{id}/access", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.setUserAccess))))
	mux.Handle("POST /api/v1/users/{id}/approve", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.approveUser))))
	mux.Handle("GET /api/v1/roles", s.requireSession(http.HandlerFunc(s.listRoles)))
	mux.Handle("POST /api/v1/roles", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.createRole))))
	mux.Handle("PUT /api/v1/roles/{id}", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.updateRole))))
	mux.Handle("DELETE /api/v1/roles/{id}", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.deleteRole))))
	mux.Handle("GET /api/v1/permissions", s.requireSession(http.HandlerFunc(s.listPermissions)))
	mux.Handle("POST /api/v1/permissions", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.createPermission))))
	mux.Handle("DELETE /api/v1/permissions/{name}", s.requireSession(s.requireSameOrigin(http.HandlerFunc(s.deletePermission))))
	return s.recover(s.logRequests(s.securityHeaders(mux)))
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if !s.installed.Load() {
		http.Redirect(w, r, "/install", http.StatusSeeOther)
		return
	}
	s.renderManagementLogin(w, r)
}

func (s *Server) clientLoginPage(w http.ResponseWriter, r *http.Request) {
	s.renderClientLogin(w, r)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r)
	console, err := s.store.HasConsoleAccess(r.Context(), claims.UserID)
	if err != nil {
		s.internalError(w, "check console access", err)
		return
	}
	if console {
		s.serveEmbedded(w, "index.html")
		return
	}
	member, err := s.store.HasMembership(r.Context(), claims.UserID)
	if err != nil {
		s.internalError(w, "check membership", err)
		return
	}
	if member {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}
	s.serveEmbedded(w, "waiting-room.html")
}

func (s *Server) docs(w http.ResponseWriter, _ *http.Request) {
	s.serveEmbedded(w, "docs.html")
}

func (s *Server) openapi(w http.ResponseWriter, _ *http.Request) {
	s.serveEmbedded(w, "openapi.json")
}

func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	name := path.Base(r.PathValue("name"))
	if name != "style.css" && name != "app.js" && name != "profile.js" && name != "roles.js" &&
		name != "account.js" {
		http.NotFound(w, r)
		return
	}
	s.serveEmbedded(w, name)
}

func (s *Server) serveEmbedded(w http.ResponseWriter, name string) {
	content, err := web.Files.ReadFile(name)
	if err != nil {
		http.Error(w, "asset unavailable", http.StatusInternalServerError)
		return
	}

	body := content
	// HTML pages get the theme origin substituted in. It is a placeholder rather than
	// a literal because the origin is deployment configuration, not build-time.
	//
	// With no origin configured the two theme lines are removed outright rather than
	// emitted with an empty href. An empty href is a same-origin request to this
	// application, which 404s: a broken stylesheet request in the console, and a
	// styling bug report that points at the wrong service entirely.
	if path.Ext(name) == ".html" {
		body = applyThemeOrigin(content, s.cfg.ThemeBaseURL)
	}

	w.Header().Set("Content-Type", mime.TypeByExtension(path.Ext(name)))
	w.Write(body)
}

// themeOriginPlaceholder is substituted into every HTML page. It is deliberately not
// valid markup, so an unsubstituted page is obviously wrong rather than subtly so.
const themeOriginPlaceholder = "__GO_LOOSE_THEME_ORIGIN__"

// applyThemeOrigin substitutes the theme origin into an HTML page, or removes the
// theme lines entirely when none is configured.
func applyThemeOrigin(content []byte, base string) []byte {
	// TrimSpace as well as the trailing slash: an environment variable set to spaces
	// is a plausible accident, and it would otherwise produce a relative URL that
	// resolves against this application and 404s.
	origin := strings.TrimRight(strings.TrimSpace(base), "/")
	if origin == "" {
		return dropThemeLines(content)
	}
	return bytes.ReplaceAll(content, []byte(themeOriginPlaceholder), []byte(origin))
}

// dropThemeLines removes every line carrying a theme marker attribute. Markers are
// used rather than the placeholder itself so that the <link> and the <script> can both
// be removed: substituting an empty origin into the script URL would leave a module
// import of this application's own /rt/v1/components.js, which does not exist.
func dropThemeLines(content []byte) []byte {
	lines := bytes.Split(content, []byte("\n"))
	kept := make([][]byte, 0, len(lines))
	for _, line := range lines {
		if bytes.Contains(line, []byte(themeMarkerContract)) || bytes.Contains(line, []byte(themeMarkerScript)) {
			continue
		}
		kept = append(kept, line)
	}
	return bytes.Join(kept, []byte("\n"))
}

// Marker attributes on the theme lines, used only to find and remove them.
const (
	themeMarkerContract = "data-theme-contract"
	themeMarkerScript   = "data-bananas-components"
)

func (s *Server) authStart(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("return") != "" || s.requestTenantSlug(r.Host) != "" {
		http.NotFound(w, r)
		return
	}
	target := "/"
	state, err := s.newLoginState(target)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start login")
		return
	}
	oauthConfig, verifier := s.oidcConfiguration()
	if oauthConfig == nil || verifier == nil {
		if s.cfg.DevLogin {
			http.Redirect(w, r, "/auth/dev?state="+url.QueryEscape(state), http.StatusSeeOther)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "OIDC is not configured")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "go_loose_oauth_state", Value: state, Path: "/auth/callback", Domain: s.oauthStateCookieDomain(r),
		HttpOnly: true, Secure: strings.HasPrefix(s.cfg.BaseURL, "https://"),
		SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
	http.Redirect(w, r, oauthConfig.AuthCodeURL(state), http.StatusFound)
}

func (s *Server) authCallback(w http.ResponseWriter, r *http.Request) {
	stateCookie, cookieErr := r.Cookie("go_loose_oauth_state")
	if cookieErr != nil || stateCookie.Value != r.URL.Query().Get("state") {
		writeError(w, http.StatusBadRequest, "invalid OIDC state")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "go_loose_oauth_state", Value: "", Path: "/auth/callback", Domain: s.oauthStateCookieDomain(r),
		HttpOnly: true, Secure: strings.HasPrefix(s.cfg.BaseURL, "https://"), MaxAge: -1,
	})
	target, err := s.loginTargetFromState(r.URL.Query().Get("state"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid OIDC state")
		return
	}
	oauthConfig, verifier := s.oidcConfiguration()
	if oauthConfig == nil || verifier == nil {
		writeError(w, http.StatusServiceUnavailable, "OIDC is not configured")
		return
	}
	oauthToken, err := oauthConfig.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "OIDC code exchange failed")
		return
	}
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		writeError(w, http.StatusUnauthorized, "identity provider did not return an ID token")
		return
	}
	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid ID token")
		return
	}
	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
		Name    string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.Subject == "" || claims.Email == "" {
		writeError(w, http.StatusUnauthorized, "identity claims are incomplete")
		return
	}
	if !s.emailAllowed(claims.Email) {
		writeError(w, http.StatusForbidden, "email domain is not allowed")
		return
	}
	if claims.Name == "" {
		claims.Name = claims.Email
	}
	s.finishLogin(w, r, claims.Subject, claims.Email, claims.Name, target, true)
}

func (s *Server) authDev(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DevLogin {
		http.NotFound(w, r)
		return
	}
	target, err := s.loginTargetFromState(r.URL.Query().Get("state"))
	if r.URL.Query().Get("state") == "" {
		target, err = "/", nil
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid development login state")
		return
	}
	s.finishLogin(w, r, "dev:"+s.cfg.DevUser, s.cfg.DevUser, "Local Administrator", target, false)
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, subject, email, name, target string, claimSystemAdministrator bool) {
	user, err := s.store.UpsertUser(r.Context(), subject, email, name)
	if err != nil {
		s.logger.Error("upsert user", "error", err)
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	if claimSystemAdministrator {
		if _, err := s.store.ClaimFirstSystemAdministrator(r.Context(), user.ID); err != nil {
			s.logger.Error("claim first system administrator", "error", err)
			writeError(w, http.StatusInternalServerError, "login setup failed")
			return
		}
	}
	claims := session.Claims{
		UserID: user.ID, Email: user.Email, DisplayName: user.DisplayName, Management: target == "/",
	}
	var sessionErr error
	if target == "/" {
		sessionErr = s.sessions.Set(w, claims)
	} else {
		sessionErr = s.sessions.SetShared(w, claims, s.cfg.AuthDomain)
	}
	if sessionErr != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// authLogout ends the session and, where the identity provider supports it, the
// provider session the rest of the family shares.
//
// Three things happen, in this order, and the order matters:
//
//  1. Every hosted-login session the user holds is revoked. Go Loose issues those
//     bearer tokens, so this is what actually signs the user out of the tenant
//     applications: their tokens stop resolving the moment this runs, without the
//     other application being told or having to ask. It happens before the local
//     cookie is cleared, because the user id is only available while the session
//     still exists.
//  2. The local management cookies are cleared.
//  3. The browser is sent to the identity provider's logout endpoint, so the single
//     sign-on session that every application in the family relies on ends too. If
//     the provider does not advertise an endpoint, this step is skipped and the user
//     lands back on the sign-in page: the local sign-out still happened, and the
//     other applications end at their next token check rather than immediately.
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	// Read before clearing. A missing or expired session is not a failure to sign
	// out, so the claims are best effort and the sign-out proceeds regardless.
	claims, err := s.sessions.Get(r)
	if err == nil {
		if revoked, revokeErr := s.store.RevokeUserClientSessions(r.Context(), claims.UserID); revokeErr != nil {
			s.logger.Error("revoke client sessions on logout", "error", revokeErr)
		} else if revoked > 0 {
			s.logger.Info("revoked client sessions on logout", "count", revoked, "user", claims.UserID)
		}
	}

	s.sessions.Clear(w)
	s.sessions.ClearShared(w, s.cfg.AuthDomain)

	if target := s.providerLogoutURL(r); target != "" {
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// providerLogoutURL builds the identity provider logout URL, or an empty string when
// this installation has no provider endpoint to send the browser to.
//
// The client id is sent instead of an id_token_hint deliberately. A hint would be
// the precise way to end one particular provider session, but it means keeping a
// live credential in the browser cookie between login and logout, and the cookie has
// a size budget this codebase should not spend on it. Providers accept the client id
// and the post-logout redirect on their own.
func (s *Server) providerLogoutURL(r *http.Request) string {
	endpoint, clientID := s.logoutConfiguration()
	if endpoint == "" || clientID == "" {
		return ""
	}
	target, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	query := target.Query()
	query.Set("client_id", clientID)
	// Bounce back to the sign-in page so the provider has somewhere valid to send
	// the browser. An unregistered redirect target is silently ignored by some
	// providers, which would leave the user on the provider's own page.
	query.Set("post_logout_redirect_uri", s.absoluteURL(r, "/login"))
	target.RawQuery = query.Encode()
	return target.String()
}

// absoluteURL resolves a local path against the request, honouring the address the
// client actually used so that a tenant host does not receive a link to the apex.
//
// The request wins over cfg.BaseURL. BaseURL is a configuration value that is
// routinely absent or stale -- it defaults to http://localhost:8080 -- so building
// a link from it hands the browser an address it cannot load, and a page served
// under a Content-Security-Policy of 'self' refuses it outright. The request's own
// host is the one address known to be both reachable and same-origin.
func (s *Server) absoluteURL(r *http.Request, path string) string {
	if r != nil && r.Host != "" {
		return s.requestScheme(r) + "://" + r.Host + path
	}
	if parsed, err := url.Parse(s.cfg.BaseURL); err == nil && parsed.Host != "" {
		return parsed.Scheme + "://" + parsed.Host + path
	}
	return path
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r)
	allowed, err := s.store.HasConsoleAccess(r.Context(), claims.UserID)
	if err != nil {
		s.internalError(w, "check console access", err)
		return
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "this account has no console access")
		return
	}
	tenants, err := s.store.ListTenants(r.Context(), claims.UserID)
	if err != nil {
		s.internalError(w, "list tenants", err)
		return
	}
	applications, err := s.store.ListApplications(r.Context(), claims.UserID)
	if err != nil {
		s.internalError(w, "list applications", err)
		return
	}
	keys, err := s.store.ListAPIKeys(r.Context(), claims.UserID)
	if err != nil {
		s.internalError(w, "list API keys", err)
		return
	}
	contracts, err := s.store.ListContracts(r.Context(), claims.UserID)
	if err != nil {
		s.internalError(w, "list contracts", err)
		return
	}
	users, err := s.store.ListManagedUsers(r.Context(), claims.UserID)
	if err != nil {
		s.internalError(w, "list users", err)
		return
	}
	pendingUsers, err := s.store.ListPendingUsers(r.Context(), claims.UserID)
	if err != nil {
		s.internalError(w, "list pending users", err)
		return
	}
	isSystemAdministrator, err := s.store.IsSystemAdministrator(r.Context(), claims.UserID)
	if err != nil {
		s.internalError(w, "check system administrator", err)
		return
	}
	catalog, err := s.store.ListPermissions(r.Context())
	if err != nil {
		s.internalError(w, "list permissions", err)
		return
	}
	profile, err := s.store.Profile(r.Context(), claims.UserID)
	if err != nil {
		s.internalError(w, "load profile", err)
		return
	}
	for index := range users {
		users[index].AvatarURL = s.avatarPath(users[index].AvatarKey)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user": claims, "profile": s.profileResponse(profile),
		"tenants": tenants, "applications": applications, "keys": keys, "contracts": contracts,
		"users": users, "pending_users": pendingUsers, "permissions": catalog,
		"is_system_administrator": isSystemAdministrator,
	})
}

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	isSystemAdministrator, err := s.store.IsSystemAdministrator(r.Context(), claimsFrom(r).UserID)
	if err != nil {
		s.internalError(w, "check system administrator", err)
		return
	}
	if !isSystemAdministrator {
		writeError(w, http.StatusForbidden, "system administrator access required")
		return
	}
	var request struct{ Slug, Name string }
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Slug, request.Name = strings.TrimSpace(request.Slug), strings.TrimSpace(request.Name)
	if !validSlug(request.Slug) || request.Name == "" {
		writeError(w, http.StatusBadRequest, "name and a valid lowercase slug are required")
		return
	}
	item, err := s.store.CreateTenant(r.Context(), claimsFrom(r).UserID, request.Slug, request.Name)
	if err != nil {
		if errors.Is(err, store.ErrTenantSlugTaken) {
			writeError(w, http.StatusConflict, "a tenant with this slug already exists")
			return
		}
		s.internalError(w, "create tenant", err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) createApplication(w http.ResponseWriter, r *http.Request) {
	var request store.Application
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Name, request.Slug = strings.TrimSpace(request.Name), strings.TrimSpace(request.Slug)
	if request.TenantID == "" || request.Name == "" || !validSlug(request.Slug) {
		writeError(w, http.StatusBadRequest, "tenant, name, and a valid lowercase slug are required")
		return
	}
	for i := range request.AllowedHosts {
		request.AllowedHosts[i] = strings.ToLower(strings.TrimSpace(request.AllowedHosts[i]))
		if strings.ContainsAny(request.AllowedHosts[i], "/:") {
			writeError(w, http.StatusBadRequest, "allowed hosts must be hostnames without schemes or ports")
			return
		}
	}
	item, err := s.store.CreateApplication(r.Context(), claimsFrom(r).UserID, request)
	if err != nil {
		s.handleStoreError(w, "create application", err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ApplicationID string     `json:"application_id"`
		Name          string     `json:"name"`
		ExpiresAt     *time.Time `json:"expires_at"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	if request.ApplicationID == "" || request.Name == "" || (request.ExpiresAt != nil && !request.ExpiresAt.After(time.Now())) {
		writeError(w, http.StatusBadRequest, "application, name, and a future expiration are required")
		return
	}
	plain, prefix, hash, err := key.Generate()
	if err != nil {
		s.internalError(w, "generate API key", err)
		return
	}
	item, err := s.store.CreateAPIKey(r.Context(), claimsFrom(r).UserID, request.ApplicationID, request.Name, prefix, hash, request.ExpiresAt)
	if err != nil {
		s.handleStoreError(w, "create API key", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"key": item, "secret": plain})
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RevokeAPIKey(r.Context(), claimsFrom(r).UserID, r.PathValue("id")); err != nil {
		s.handleStoreError(w, "revoke API key", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	plain := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if plain == "" {
		authorization := r.Header.Get("Authorization")
		if strings.HasPrefix(authorization, "Bearer ") {
			plain = strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
		}
	}
	if key.ValidateFormat(plain) != nil {
		writeError(w, http.StatusUnauthorized, "a valid X-API-Key header is required")
		return
	}
	var request struct {
		Tenant      string `json:"tenant"`
		Application string `json:"application"`
		Method      string `json:"method"`
		Path        string `json:"path"`
		Host        string `json:"host"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Method = strings.ToUpper(strings.TrimSpace(request.Method))
	request.Host = strings.ToLower(strings.TrimSpace(request.Host))
	if request.Application == "" || request.Method == "" || !strings.HasPrefix(request.Path, "/") {
		writeError(w, http.StatusBadRequest, "application, method, and an absolute path are required")
		return
	}
	result, err := s.store.Authorize(r.Context(), key.Hash(plain), request.Tenant, request.Application, request.Method, request.Path, request.Host)
	if err != nil {
		s.internalError(w, "authorize request", err)
		return
	}
	if !result.Allowed {
		writeJSON(w, http.StatusForbidden, result)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) createContract(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ApplicationID string `json:"application_id"`
		SourceType    string `json:"source_type"`
		SourceURL     string `json:"source_url"`
		Document      string `json:"document"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	var content []byte
	var sourceURL *string
	if request.SourceType == "url" {
		parsed, err := contract.ValidateSourceURL(request.SourceURL, s.cfg.AllowPrivateContractURL)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		content, err = s.fetchContract(r.Context(), parsed)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		value := parsed.String()
		sourceURL = &value
	} else {
		content = []byte(request.Document)
		if request.SourceURL != "" {
			sourceURL = &request.SourceURL
		}
	}
	if len(content) == 0 {
		writeError(w, http.StatusBadRequest, "an OpenAPI document or source URL is required")
		return
	}
	document, err := contract.Parse(content)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	item, err := s.store.SaveContract(r.Context(), claimsFrom(r).UserID, request.ApplicationID, document, sourceURL)
	if err != nil {
		s.handleStoreError(w, "save contract", err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) fetchContract(ctx context.Context, source *url.URL) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.String(), nil)
	if err != nil {
		return nil, errors.New("could not create contract request")
	}
	request.Header.Set("Accept", "application/json, application/yaml, text/yaml")
	response, err := s.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch contract: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("contract source returned HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, 5<<20+1))
	if err != nil {
		return nil, fmt.Errorf("read contract: %w", err)
	}
	if len(content) > 5<<20 {
		return nil, errors.New("contract exceeds 5 MiB")
	}
	return content, nil
}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.installed.Load() {
			http.Redirect(w, r, "/install", http.StatusSeeOther)
			return
		}
		claims, err := s.sessions.Get(r)
		if err != nil || !claims.Management {
			if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/openapi.json" {
				writeError(w, http.StatusUnauthorized, "authentication required")
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey, claims)))
	})
}

// requireSameOrigin rejects state-changing requests that did not come from the
// page the session cookie belongs to.
//
// The comparison is made against the origin the request actually arrived on
// rather than against cfg.BaseURL alone. A deployment whose configured base URL
// disagrees with the address users browse to -- a reverse proxy terminating TLS,
// a tenant subdomain, or simply a stale GO_LOOSE_BASE_URL -- would otherwise
// reject every legitimate write. Deriving the scheme from the request keeps the
// check anchored to r.Host, which is the part an attacker cannot influence: the
// browser sets Origin itself and it always names the page's own host.
func (s *Server) requireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source := r.Header.Get("Origin")
		if source == "" {
			source = r.Header.Get("Referer")
		}
		sourceURL, err := url.Parse(source)
		if err != nil || !s.originAllowed(sourceURL, r) {
			writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originAllowed reports whether source names the same origin as the request.
// The configured base URL is accepted as well so that installations which
// advertise a canonical address keep working when a request reaches the server
// through a different but still legitimate hostname.
func (s *Server) originAllowed(source *url.URL, r *http.Request) bool {
	if source.Host == "" {
		return false
	}
	baseScheme, baseHost := baseOrigin(s.cfg.BaseURL)
	for _, candidate := range [][2]string{
		{s.requestScheme(r), r.Host},
		{baseScheme, baseHost},
	} {
		scheme, host := candidate[0], candidate[1]
		if host == "" {
			continue
		}
		if strings.EqualFold(source.Host, host) && strings.EqualFold(source.Scheme, scheme) {
			return true
		}
	}
	return false
}

// requestScheme reports the scheme the client used to reach this server. A
// reverse proxy terminates TLS before the request arrives, so the forwarded
// protocol takes precedence over the local connection state.
func (s *Server) requestScheme(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		if scheme, _, found := strings.Cut(forwarded, ","); found {
			return strings.TrimSpace(scheme)
		}
		return strings.TrimSpace(forwarded)
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// baseOrigin splits a configured base URL into its scheme and host, returning
// empty strings when the value is missing or unparseable.
func baseOrigin(baseURL string) (scheme, host string) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", ""
	}
	return parsed.Scheme, parsed.Host
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://unpkg.com; script-src 'self' 'unsafe-inline' https://unpkg.com; connect-src 'self'; img-src 'self' data:; font-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Info("http request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic recovered", "value", recovered)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) emailAllowed(email string) bool {
	if len(s.cfg.AllowedEmailDomains) == 0 {
		return true
	}
	parts := strings.Split(strings.ToLower(email), "@")
	if len(parts) != 2 {
		return false
	}
	for _, domain := range s.cfg.AllowedEmailDomains {
		if parts[1] == domain {
			return true
		}
	}
	return false
}

func (s *Server) oauthStateCookieDomain(r *http.Request) string {
	host := strings.ToLower(r.Host)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	if host == s.cfg.AuthDomain || strings.HasSuffix(host, "."+s.cfg.AuthDomain) {
		return s.cfg.AuthDomain
	}
	return ""
}

func (s *Server) internalError(w http.ResponseWriter, operation string, err error) {
	s.logger.Error(operation, "error", err)
	writeError(w, http.StatusInternalServerError, "internal server error")
}

func (s *Server) handleStoreError(w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "resource not found or permission denied")
		return
	}
	s.internalError(w, operation, err)
}

func claimsFrom(r *http.Request) session.Claims {
	return r.Context().Value(claimsKey).(session.Claims)
}

func validSlug(value string) bool {
	if len(value) < 2 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	return decodeJSONLimit(w, r, 6<<20, target)
}

func decodeJSONLimit(w http.ResponseWriter, r *http.Request, limit int64, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "request must contain one JSON object")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Error("encode response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
