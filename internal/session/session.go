package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const cookieName = "go_loose_session"

type Claims struct {
	UserID      string `json:"uid"`
	Email       string `json:"email"`
	DisplayName string `json:"name"`
	Management  bool   `json:"management"`
	ExpiresAt   int64  `json:"exp"`
}

type Manager struct {
	secret []byte
	secure bool
}

func New(secret string, secure bool) *Manager {
	return &Manager{secret: []byte(secret), secure: secure}
}

func (m *Manager) Set(w http.ResponseWriter, claims Claims) error {
	return m.set(w, claims, "")
}

func (m *Manager) SetShared(w http.ResponseWriter, claims Claims, domain string) error {
	return m.set(w, claims, domain)
}

func (m *Manager) set(w http.ResponseWriter, claims Claims, domain string) error {
	claims.ExpiresAt = time.Now().Add(12 * time.Hour).Unix()
	payload, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	value := encoded + "." + m.sign(encoded)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: value, Path: "/", HttpOnly: true, Secure: m.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int((12 * time.Hour).Seconds()), Domain: domain,
	})
	return nil
}

func (m *Manager) Get(r *http.Request) (Claims, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return Claims{}, err
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(m.sign(parts[0]))) {
		return Claims{}, errors.New("invalid session signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, errors.New("invalid session encoding")
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, errors.New("invalid session payload")
	}
	if claims.UserID == "" || time.Now().Unix() >= claims.ExpiresAt {
		return Claims{}, errors.New("session expired")
	}
	return claims, nil
}

func (m *Manager) Clear(w http.ResponseWriter) {
	m.clear(w, "")
}

func (m *Manager) ClearShared(w http.ResponseWriter, domain string) {
	m.clear(w, domain)
}

func (m *Manager) clear(w http.ResponseWriter, domain string) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", HttpOnly: true, Secure: m.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1, Domain: domain,
	})
}

func (m *Manager) NewState() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (m *Manager) SignedState(state string) string {
	return state + "." + m.sign(state)
}

func (m *Manager) VerifyState(value string) bool {
	_, ok := m.VerifySigned(value)
	return ok
}

func (m *Manager) VerifySigned(value string) (string, bool) {
	index := strings.LastIndexByte(value, '.')
	if index <= 0 || index == len(value)-1 {
		return "", false
	}
	payload, signature := value[:index], value[index+1:]
	return payload, hmac.Equal([]byte(signature), []byte(m.sign(payload)))
}

func (m *Manager) sign(value string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
