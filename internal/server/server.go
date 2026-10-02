package server

import (
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
	cfg        config.Config
	store      *store.Store
	db         *sql.DB
	sessions   *session.Manager
	oauth      *oauth2.Config
	verifier   *oidc.IDTokenVerifier
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
		if err := server.configureOIDC(ctx, installation.OIDCIssuer, installation.OIDCClientID, secret); err != nil {
			return nil, err
		}
		server.installed.Store(true)
		if err := server.ensureLocalAdministrator(ctx); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("load installation: %w", err)
	} else if cfg.OIDCIssuer != "" && cfg.OIDCClientID != "" && cfg.OIDCClientSecret != "" {
		if err := server.configureOIDC(ctx, cfg.OIDCIssuer, cfg.OIDCClientID, cfg.OIDCClientSecret); err != nil {
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
	mux.HandleFunc("POST /api/v1/authorize", s.authorize)
	mux.HandleFunc("GET /connect/authorize", s.clientAuthorize)
	mux.HandleFunc("POST /connect/token", s.clientToken)
	mux.HandleFunc("GET /connect/userinfo", s.clientUserInfo)
	mux.HandleFunc("POST /connect/logout", s.clientLogout)
	mux.HandleFunc("GET /client/login", s.clientLoginPage)

	// {$} matches only "/". The unanchored pattern "GET /" is a catch-all, so a
	// browser favicon request would redirect to /install and rotate its CSRF cookie.
	mux.Handle("GET /{$}", s.requireSession(http.HandlerFunc(s.index)))
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
	allowed, err := s.store.HasManagementAccess(r.Context(), claimsFrom(r).UserID)
	if err != nil {
		s.internalError(w, "check management access", err)
		return
	}
	if !allowed {
		s.serveEmbedded(w, "waiting-room.html")
		return
	}
	s.serveEmbedded(w, "index.html")
}

func (s *Server) docs(w http.ResponseWriter, _ *http.Request) {
	s.serveEmbedded(w, "docs.html")
}

func (s *Server) openapi(w http.ResponseWriter, _ *http.Request) {
	s.serveEmbedded(w, "openapi.json")
}

func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	name := path.Base(r.PathValue("name"))
	if name != "style.css" && name != "app.js" {
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
	w.Header().Set("Content-Type", mime.TypeByExtension(path.Ext(name)))
	w.Write(content)
}

func (s *Server) authStart(w http.ResponseWriter, r *http.Request) {
	target := "/"
	if requested := r.URL.Query().Get("return"); requested != "" {
		validated, err := s.validateLoginReturn(r.Context(), requested)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid client login return URL")
			return
		}
		target = validated
	}
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

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	s.sessions.Clear(w)
	s.sessions.ClearShared(w, s.cfg.AuthDomain)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r)
	allowed, err := s.store.HasManagementAccess(r.Context(), claims.UserID)
	if err != nil {
		s.internalError(w, "check management access", err)
		return
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "waiting for administrator approval")
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
	writeJSON(w, http.StatusOK, map[string]any{
		"user": claims, "tenants": tenants, "applications": applications, "keys": keys, "contracts": contracts,
		"users": users, "pending_users": pendingUsers, "is_system_administrator": isSystemAdministrator,
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

func (s *Server) requireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source := r.Header.Get("Origin")
		if source == "" {
			source = r.Header.Get("Referer")
		}
		sourceURL, sourceErr := url.Parse(source)
		baseURL, baseErr := url.Parse(s.cfg.BaseURL)
		if sourceErr != nil || baseErr != nil || sourceURL.Scheme != baseURL.Scheme || sourceURL.Host != baseURL.Host {
			writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		next.ServeHTTP(w, r)
	})
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
	r.Body = http.MaxBytesReader(w, r.Body, 6<<20)
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
