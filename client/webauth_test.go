package client

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestBrowserLoginRedirect(t *testing.T) {
	auth, err := NewBrowserAuth(BrowserAuthConfig{
		BaseURL: "https://nmbs.goloose.local", ClientID: "client",
		ClientSecret: "secret", RedirectURL: "https://nmbs.guess.local/auth/callback",
	})
	if err != nil {
		t.Fatalf("NewBrowserAuth() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	auth.LoginHandler(recorder, httptest.NewRequest(http.MethodGet, "/login", nil))
	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d", recorder.Code)
	}
	target, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if target.Path != "/connect/authorize" || target.Query().Get("client_id") != "client" || target.Query().Get("state") == "" {
		t.Fatalf("unexpected redirect: %s", target)
	}
	if len(recorder.Result().Cookies()) != 1 || !recorder.Result().Cookies()[0].HttpOnly {
		t.Fatal("expected an HTTP-only state cookie")
	}
}

func TestBrowserMiddlewareAddsUser(t *testing.T) {
	identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer session-token" {
			t.Fatal("missing bearer token")
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"user-1","email":"user@example.com","tenant_slug":"nmbs","application":"guess"}`))
	}))
	defer identity.Close()
	auth, err := NewBrowserAuth(BrowserAuthConfig{
		BaseURL: identity.URL, ClientID: "client", ClientSecret: "secret",
		RedirectURL: "http://localhost/auth/callback",
	})
	if err != nil {
		t.Fatalf("NewBrowserAuth() error = %v", err)
	}
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFromContext(r.Context())
		if !ok || user.Email != "user@example.com" {
			t.Fatalf("unexpected user: %#v", user)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://localhost/private", nil)
	request.AddCookie(&http.Cookie{Name: defaultSessionCookie, Value: "session-token"})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestBrowserCallbackUsesBasicClientAuthentication(t *testing.T) {
	identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, secret, ok := r.BasicAuth()
		if !ok || clientID != "client-id" || secret != "client-secret" {
			t.Fatalf("unexpected client authentication: %q, %q, %v", clientID, secret, ok)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"session-token","expires_in":3600}`))
	}))
	defer identity.Close()
	auth, err := NewBrowserAuth(BrowserAuthConfig{
		BaseURL: identity.URL, ClientID: "client-id", ClientSecret: "client-secret",
		RedirectURL: "http://localhost/auth/callback",
	})
	if err != nil {
		t.Fatalf("NewBrowserAuth() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/auth/callback?code=one-time-code&state=login-state", nil)
	request.AddCookie(&http.Cookie{Name: stateCookie, Value: "login-state"})
	recorder := httptest.NewRecorder()
	auth.CallbackHandler(recorder, request)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var session *http.Cookie
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == defaultSessionCookie {
			session = cookie
		}
	}
	if session == nil || session.Value != "session-token" || !session.HttpOnly {
		t.Fatalf("unexpected session cookie: %#v", session)
	}
}
