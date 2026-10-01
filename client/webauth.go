package client

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultSessionCookie = "go_loose_user_session"
	stateCookie          = "go_loose_login_state"
)

type BrowserAuthConfig struct {
	BaseURL        string
	ClientID       string
	ClientSecret   string
	RedirectURL    string
	AfterLoginURL  string
	AfterLogoutURL string
	LoginPath      string
	CookieName     string
	CookieSecure   bool
	HTTPClient     *http.Client
}

type BrowserAuth struct {
	config BrowserAuthConfig
}

type User struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	DisplayName   string `json:"display_name"`
	TenantID      string `json:"tenant_id"`
	TenantSlug    string `json:"tenant_slug"`
	ApplicationID string `json:"application_id"`
	Application   string `json:"application"`
}

type userContextKey struct{}

func NewBrowserAuth(config BrowserAuthConfig) (*BrowserAuth, error) {
	if config.BaseURL == "" || config.ClientID == "" || config.ClientSecret == "" || config.RedirectURL == "" {
		return nil, errors.New("browser auth requires BaseURL, ClientID, ClientSecret, and RedirectURL")
	}
	redirect, err := url.Parse(config.RedirectURL)
	if err != nil || !redirect.IsAbs() {
		return nil, errors.New("RedirectURL must be absolute")
	}
	config.BaseURL = strings.TrimRight(config.BaseURL, "/")
	if config.AfterLoginURL == "" {
		config.AfterLoginURL = "/"
	}
	if config.AfterLogoutURL == "" {
		config.AfterLogoutURL = "/"
	}
	if config.LoginPath == "" {
		config.LoginPath = "/login"
	}
	if config.CookieName == "" {
		config.CookieName = defaultSessionCookie
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &BrowserAuth{config: config}, nil
}

func (a *BrowserAuth) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randomValue(24)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Value: state, Path: callbackPath(a.config.RedirectURL),
		HttpOnly: true, Secure: a.config.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
	query := url.Values{
		"response_type": {"code"}, "client_id": {a.config.ClientID},
		"redirect_uri": {a.config.RedirectURL}, "state": {state},
	}
	http.Redirect(w, r, a.config.BaseURL+"/connect/authorize?"+query.Encode(), http.StatusFound)
}

func (a *BrowserAuth) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	state, err := r.Cookie(stateCookie)
	if err != nil || state.Value == "" || subtle.ConstantTimeCompare([]byte(state.Value), []byte(r.URL.Query().Get("state"))) != 1 {
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "authorization code missing", http.StatusBadRequest)
		return
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {a.config.RedirectURL},
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, a.config.BaseURL+"/connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, "could not complete login", http.StatusInternalServerError)
		return
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(a.config.ClientID, a.config.ClientSecret)
	response, err := a.config.HTTPClient.Do(request)
	if err != nil {
		http.Error(w, "identity service unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&tokenResponse); err != nil || response.StatusCode != http.StatusOK || tokenResponse.AccessToken == "" {
		http.Error(w, "authorization code exchange failed", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: a.config.CookieName, Value: tokenResponse.AccessToken, Path: "/",
		HttpOnly: true, Secure: a.config.CookieSecure, SameSite: http.SameSiteLaxMode,
		MaxAge: tokenResponse.ExpiresIn,
	})
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: callbackPath(a.config.RedirectURL), MaxAge: -1, HttpOnly: true})
	http.Redirect(w, r, a.config.AfterLoginURL, http.StatusSeeOther)
}

func (a *BrowserAuth) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	var revokeErr error
	if cookie, err := r.Cookie(a.config.CookieName); err == nil {
		request, requestErr := http.NewRequestWithContext(r.Context(), http.MethodPost, a.config.BaseURL+"/connect/logout", nil)
		if requestErr != nil {
			revokeErr = requestErr
		} else {
			request.Header.Set("Authorization", "Bearer "+cookie.Value)
			response, responseErr := a.config.HTTPClient.Do(request)
			if responseErr != nil {
				revokeErr = responseErr
			} else {
				response.Body.Close()
				if response.StatusCode != http.StatusNoContent {
					revokeErr = fmt.Errorf("Go Loose logout returned HTTP %d", response.StatusCode)
				}
			}
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: a.config.CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.config.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
	if revokeErr != nil {
		http.Error(w, "local session cleared, but central session revocation failed", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, a.config.AfterLogoutURL, http.StatusSeeOther)
}

func (a *BrowserAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(a.config.CookieName)
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, a.config.LoginPath, http.StatusSeeOther)
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, a.config.BaseURL+"/connect/userinfo", nil)
		if err != nil {
			http.Error(w, "could not validate session", http.StatusInternalServerError)
			return
		}
		request.Header.Set("Authorization", "Bearer "+cookie.Value)
		response, err := a.config.HTTPClient.Do(request)
		if err != nil {
			http.Error(w, "identity service unavailable", http.StatusServiceUnavailable)
			return
		}
		defer response.Body.Close()
		var user User
		if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&user) != nil {
			http.SetCookie(w, &http.Cookie{Name: a.config.CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
			http.Redirect(w, r, a.config.LoginPath, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userContextKey{}, user)))
	})
}

func UserFromContext(ctx context.Context) (User, bool) {
	user, ok := ctx.Value(userContextKey{}).(User)
	return user, ok
}

func randomValue(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func callbackPath(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}
