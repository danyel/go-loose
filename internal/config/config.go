package config

import (
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr                    string
	BaseURL                 string
	AuthDomain              string
	DatabaseURL             string
	SessionSecret           string
	DevLogin                bool
	DevUser                 string
	LocalLogin              bool
	LocalAdminEmail         string
	LocalAdminPassword      string
	OIDCIssuer              string
	OIDCClientID            string
	OIDCClientSecret        string
	OIDCRedirectURL         string
	AllowedEmailDomains     []string
	AllowPrivateContractURL bool
	BootstrapTenant         string
	BootstrapApp            string
	HTTPTimeout             time.Duration
}

func Load() (Config, error) {
	baseURL := strings.TrimRight(env("GO_LOOSE_BASE_URL", "http://localhost:8080"), "/")
	cfg := Config{
		Addr:                    env("GO_LOOSE_ADDR", ":8080"),
		BaseURL:                 baseURL,
		AuthDomain:              strings.TrimPrefix(strings.ToLower(env("GO_LOOSE_AUTH_DOMAIN", "auth.dev")), "."),
		DatabaseURL:             env("GO_LOOSE_DATABASE_URL", "postgres://goloose:goloose@localhost:5432/goloose?sslmode=disable"),
		SessionSecret:           os.Getenv("GO_LOOSE_SESSION_SECRET"),
		DevLogin:                envBool("GO_LOOSE_DEV_LOGIN", false),
		DevUser:                 env("GO_LOOSE_DEV_USER", "admin@local.test"),
		LocalLogin:              envBool("GO_LOOSE_LOCAL_LOGIN", false),
		LocalAdminEmail:         strings.ToLower(env("GO_LOOSE_LOCAL_ADMIN_EMAIL", "admin@goloose.local")),
		LocalAdminPassword:      os.Getenv("GO_LOOSE_LOCAL_ADMIN_PASSWORD"),
		OIDCIssuer:              strings.TrimRight(os.Getenv("GO_LOOSE_OIDC_ISSUER"), "/"),
		OIDCClientID:            os.Getenv("GO_LOOSE_OIDC_CLIENT_ID"),
		OIDCClientSecret:        os.Getenv("GO_LOOSE_OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:         env("GO_LOOSE_OIDC_REDIRECT_URL", baseURL+"/auth/callback"),
		AllowedEmailDomains:     csv(os.Getenv("GO_LOOSE_ALLOWED_EMAIL_DOMAINS")),
		AllowPrivateContractURL: envBool("GO_LOOSE_ALLOW_PRIVATE_CONTRACT_URLS", false),
		BootstrapTenant:         env("GO_LOOSE_BOOTSTRAP_TENANT", "default"),
		BootstrapApp:            env("GO_LOOSE_BOOTSTRAP_APP", "default"),
		HTTPTimeout:             10 * time.Second,
	}
	if len(cfg.SessionSecret) < 32 {
		return Config{}, errors.New("GO_LOOSE_SESSION_SECRET must contain at least 32 characters")
	}
	if cfg.AuthDomain == "" || strings.ContainsAny(cfg.AuthDomain, "/:") {
		return Config{}, errors.New("GO_LOOSE_AUTH_DOMAIN must be a hostname such as auth.dev")
	}
	oidcConfigured := cfg.OIDCIssuer != "" && cfg.OIDCClientID != "" && cfg.OIDCClientSecret != ""
	if cfg.LocalAdminPassword != "" && len(cfg.LocalAdminPassword) < 12 {
		return Config{}, errors.New("GO_LOOSE_LOCAL_ADMIN_PASSWORD must contain at least 12 characters")
	}
	if oidcConfigured {
		baseURL, err := url.Parse(cfg.BaseURL)
		if err != nil || (baseURL.Hostname() != cfg.AuthDomain && !strings.HasSuffix(baseURL.Hostname(), "."+cfg.AuthDomain)) {
			return Config{}, errors.New("GO_LOOSE_BASE_URL must be inside GO_LOOSE_AUTH_DOMAIN for shared OIDC login")
		}
	}
	return cfg, nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func csv(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(strings.ToLower(item)); item != "" {
			result = append(result, item)
		}
	}
	return result
}
