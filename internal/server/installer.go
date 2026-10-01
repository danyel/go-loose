package server

import (
	"crypto/subtle"
	"html"
	"net/http"
	"strings"

	"github.com/danyel/go-loose/internal/password"
	"github.com/danyel/go-loose/internal/secretbox"
	"github.com/danyel/go-loose/internal/store"
	"github.com/danyel/go-loose/web"
)

const googleDemoClientID = "554628171917-forvpfs44pqajv77dfhl503prfqnhor3.apps.googleusercontent.com"

func (s *Server) installPage(w http.ResponseWriter, r *http.Request) {
	if s.installed.Load() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	content, err := web.Files.ReadFile("install.html")
	if err != nil {
		http.Error(w, "installer unavailable", http.StatusInternalServerError)
		return
	}
	csrfToken, err := s.installCSRFToken(w)
	if err != nil {
		http.Error(w, "could not prepare installer", http.StatusInternalServerError)
		return
	}
	page := strings.NewReplacer(
		"{{CSRF_TOKEN}}", html.EscapeString(csrfToken),
		"{{GOOGLE_CLIENT_ID}}", googleDemoClientID,
		"{{CALLBACK_URL}}", html.EscapeString(s.cfg.OIDCRedirectURL),
	).Replace(string(content))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

func (s *Server) install(w http.ResponseWriter, r *http.Request) {
	if s.installed.Load() {
		writeError(w, http.StatusConflict, "Go Loose is already installed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid installer request")
		return
	}
	csrfCookie, cookieErr := r.Cookie("go_loose_install_csrf")
	csrfValue := r.Form.Get("csrf_token")
	payload, valid := s.sessions.VerifySigned(csrfValue)
	if cookieErr != nil || subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(csrfValue)) != 1 ||
		!valid || !strings.HasPrefix(payload, "install|") {
		writeError(w, http.StatusForbidden, "invalid installer form; reload the installer")
		return
	}
	clientID := strings.TrimSpace(r.Form.Get("oidc_client_id"))
	clientSecret := strings.TrimSpace(r.Form.Get("oidc_client_secret"))
	if clientID == "" || clientSecret == "" {
		writeError(w, http.StatusBadRequest, "Google client ID and client secret are required")
		return
	}
	if err := s.configureOIDC(r.Context(), "https://accounts.google.com", clientID, clientSecret); err != nil {
		writeError(w, http.StatusBadGateway, "Google OIDC discovery failed")
		return
	}
	ciphertext, err := secretbox.Encrypt(s.cfg.SessionSecret, clientSecret)
	if err != nil {
		s.internalError(w, "encrypt OIDC secret", err)
		return
	}
	seedDemo := r.Form.Get("seed_demo") == "on"
	var demoUsers []store.DemoUser
	if seedDemo {
		demoUsers, err = buildDemoUsers()
		if err != nil {
			s.internalError(w, "hash demo credentials", err)
			return
		}
	}
	err = s.store.Install(r.Context(), store.Installation{
		OIDCIssuer: "https://accounts.google.com", OIDCClientID: clientID,
		OIDCSecretCiphertext: ciphertext, SeededDemo: seedDemo,
	}, demoUsers)
	if err != nil {
		s.internalError(w, "complete installation", err)
		return
	}
	s.installed.Store(true)
	if err := s.ensureLocalAdministrator(r.Context()); err != nil {
		s.internalError(w, "bootstrap local administrator", err)
		return
	}
	http.Redirect(w, r, "/auth/start", http.StatusSeeOther)
}

func buildDemoUsers() ([]store.DemoUser, error) {
	specs := []struct {
		email, name, password, tenant string
	}{
		{"interview@nmbs.auth.local", "NMBS Interview", "admin123", "nmbs"},
		{"interview@ypto.auth.local", "YPTO Interview", "admin123", "ypto"},
		{"reviewer@nmbs.auth.local", "NMBS Reviewer", "Demo-Nmbs-2026!", "nmbs"},
		{"reviewer@ypto.auth.local", "YPTO Reviewer", "Demo-Ypto-2026!", "ypto"},
	}
	result := make([]store.DemoUser, 0, len(specs))
	for _, spec := range specs {
		hash, err := password.HashDemo(spec.password)
		if err != nil {
			return nil, err
		}
		result = append(result, store.DemoUser{
			Email: spec.email, DisplayName: spec.name, PasswordHash: hash, TenantSlug: spec.tenant,
		})
	}
	return result, nil
}

func (s *Server) installCSRFToken(w http.ResponseWriter) (string, error) {
	state, err := s.sessions.NewState()
	if err != nil {
		return "", err
	}
	token := s.sessions.SignedState("install|" + state)
	http.SetCookie(w, &http.Cookie{
		Name: "go_loose_install_csrf", Value: token, Path: "/install",
		HttpOnly: true, Secure: strings.HasPrefix(s.cfg.BaseURL, "https://"),
		SameSite: http.SameSiteStrictMode, MaxAge: 900,
	})
	return token, nil
}
