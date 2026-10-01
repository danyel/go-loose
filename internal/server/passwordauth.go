package server

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danyel/go-loose/internal/password"
)

type loginAttempt struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

type loginGuard struct {
	mu        sync.Mutex
	attempts  map[string]loginAttempt
	dummyHash string
}

func newLoginGuard() *loginGuard {
	return &loginGuard{attempts: make(map[string]loginAttempt)}
}

func (g *loginGuard) allowed(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	attempt := g.attempts[key]
	return !now.Before(attempt.lockedUntil)
}

func (g *loginGuard) fail(key string, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	attempt := g.attempts[key]
	if attempt.windowStart.IsZero() || now.Sub(attempt.windowStart) > 10*time.Minute {
		attempt = loginAttempt{windowStart: now}
	}
	attempt.failures++
	if attempt.failures >= 5 {
		attempt.lockedUntil = now.Add(15 * time.Minute)
	}
	g.attempts[key] = attempt
	if len(g.attempts) > 10_000 {
		for itemKey, item := range g.attempts {
			if now.Sub(item.windowStart) > 30*time.Minute && now.After(item.lockedUntil) {
				delete(g.attempts, itemKey)
			}
		}
	}
}

func (g *loginGuard) success(key string) {
	g.mu.Lock()
	delete(g.attempts, key)
	g.mu.Unlock()
}

func (s *Server) passwordLogin(w http.ResponseWriter, r *http.Request) {
	if !s.installed.Load() {
		writeError(w, http.StatusServiceUnavailable, "Go Loose is not installed")
		return
	}
	if !s.cfg.LocalLogin {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid login request")
		return
	}
	csrfCookie, cookieErr := r.Cookie("go_loose_login_csrf")
	csrfValue := r.FormValue("csrf_token")
	csrfPayload, csrfValid := s.sessions.VerifySigned(csrfValue)
	if cookieErr != nil || subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(csrfValue)) != 1 ||
		!csrfValid || !strings.HasPrefix(csrfPayload, "login|") {
		writeError(w, http.StatusForbidden, "invalid login form; reload the login page")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.Form.Get("email")))
	passwordValue := r.Form.Get("password")
	target := "/"
	if requested := r.Form.Get("return"); requested != "" {
		validated, err := s.validateLoginReturn(r.Context(), requested)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid client login return URL")
			return
		}
		target = validated
	}
	remoteAddress := remoteIP(r.RemoteAddr)
	guardKey := remoteAddress + "|" + email
	now := time.Now()
	if !s.loginGuard.allowed(guardKey, now) {
		s.recordPasswordLogin(r, nil, email, remoteAddress, false, "rate_limited")
		writeError(w, http.StatusTooManyRequests, "too many login attempts; try again later")
		return
	}
	user, encoded, err := s.store.PasswordUser(r.Context(), email)
	valid := err == nil && password.Verify(encoded, passwordValue)
	if err != nil {
		password.Verify(s.loginGuard.dummyHash, passwordValue)
	}
	if !valid {
		s.loginGuard.fail(guardKey, now)
		var userID *string
		if user.ID != "" {
			userID = &user.ID
		}
		s.recordPasswordLogin(r, userID, email, remoteAddress, false, "invalid_credentials")
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	s.loginGuard.success(guardKey)
	s.recordPasswordLogin(r, &user.ID, user.Email, remoteAddress, true, "authenticated")
	s.finishLogin(w, r, "local:"+user.Email, user.Email, user.DisplayName, target, false)
}

func (s *Server) recordPasswordLogin(r *http.Request, userID *string, email, remoteAddress string, successful bool, reason string) {
	if err := s.store.RecordLogin(r.Context(), userID, email, remoteAddress, successful, reason); err != nil {
		s.logger.Error("record password login", "error", err)
	}
}

func remoteIP(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return address
}
