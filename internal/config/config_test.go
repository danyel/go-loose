package config

import "testing"

func TestLoadRequiresSessionSecret(t *testing.T) {
	t.Setenv("GO_LOOSE_SESSION_SECRET", "short")
	t.Setenv("GO_LOOSE_DEV_LOGIN", "true")
	if _, err := Load(); err == nil {
		t.Fatal("expected an error for a short session secret")
	}
}

func TestLoadDevelopmentConfiguration(t *testing.T) {
	t.Setenv("GO_LOOSE_SESSION_SECRET", "01234567890123456789012345678901")
	t.Setenv("GO_LOOSE_DEV_LOGIN", "true")
	t.Setenv("GO_LOOSE_ALLOWED_EMAIL_DOMAINS", "Example.com, internal.test")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.AllowedEmailDomains) != 2 || cfg.AllowedEmailDomains[0] != "example.com" {
		t.Fatalf("unexpected domains: %#v", cfg.AllowedEmailDomains)
	}
}

func TestLoadAllowsFirstRunWithoutConfiguredLogin(t *testing.T) {
	t.Setenv("GO_LOOSE_SESSION_SECRET", "01234567890123456789012345678901")
	t.Setenv("GO_LOOSE_DEV_LOGIN", "false")
	t.Setenv("GO_LOOSE_LOCAL_LOGIN", "false")
	t.Setenv("GO_LOOSE_OIDC_ISSUER", "")
	t.Setenv("GO_LOOSE_OIDC_CLIENT_ID", "")
	t.Setenv("GO_LOOSE_OIDC_CLIENT_SECRET", "")
	if _, err := Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadAllowsDatabaseLoginWithoutBootstrapAccount(t *testing.T) {
	t.Setenv("GO_LOOSE_SESSION_SECRET", "01234567890123456789012345678901")
	t.Setenv("GO_LOOSE_LOCAL_LOGIN", "true")
	t.Setenv("GO_LOOSE_LOCAL_ADMIN_PASSWORD", "")
	if _, err := Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadDerivesOIDCRedirectURLFromBaseURL(t *testing.T) {
	t.Setenv("GO_LOOSE_SESSION_SECRET", "01234567890123456789012345678901")
	t.Setenv("GO_LOOSE_BASE_URL", "http://auth.dev:18080/")
	t.Setenv("GO_LOOSE_OIDC_REDIRECT_URL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDCRedirectURL != "http://auth.dev:18080/auth/callback" {
		t.Fatalf("OIDC redirect URL = %q", cfg.OIDCRedirectURL)
	}
}
