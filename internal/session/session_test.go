package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionRoundTrip(t *testing.T) {
	manager := New("01234567890123456789012345678901", false)
	recorder := httptest.NewRecorder()
	if err := manager.Set(recorder, Claims{UserID: "user-1", Email: "a@example.com"}); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.AddCookie(recorder.Result().Cookies()[0])
	claims, err := manager.Get(request)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if claims.UserID != "user-1" {
		t.Fatalf("UserID = %q", claims.UserID)
	}
}

func TestRejectsTamperedSession(t *testing.T) {
	manager := New("01234567890123456789012345678901", false)
	request := httptest.NewRequest("GET", "/", nil)
	request.AddCookie(&http.Cookie{Name: cookieName, Value: "tampered.value"})
	if _, err := manager.Get(request); err == nil {
		t.Fatal("expected tampered session to fail")
	}
}

func TestSignedValueAllowsDots(t *testing.T) {
	manager := New("01234567890123456789012345678901", false)
	value := "/connect/authorize?redirect_uri=https://app.example.test/callback"
	signed := manager.SignedState(value)
	got, ok := manager.VerifySigned(signed)
	if !ok || got != value {
		t.Fatalf("VerifySigned() = %q, %v", got, ok)
	}
}
