// Package client provides fail-closed API-key authorization middleware for Go services.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const DefaultHeader = "X-API-Key"

type Config struct {
	BaseURL     string
	Tenant      string
	Application string
	Header      string
	HTTPClient  *http.Client
}

type Client struct {
	baseURL     string
	tenant      string
	application string
	header      string
	httpClient  *http.Client
}

type Principal struct {
	TenantID        string `json:"tenant_id"`
	TenantSlug      string `json:"tenant_slug"`
	ApplicationID   string `json:"application_id"`
	ApplicationSlug string `json:"application_slug"`
	APIKeyID        string `json:"api_key_id"`
	APIKeyName      string `json:"api_key_name"`
}

type authorizationResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Principal
}

const XTenantId = "X-Tenant-Id"

type contextKey struct{}

func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" || strings.TrimSpace(cfg.Application) == "" {
		return nil, errors.New("go-loose client requires BaseURL and Application")
	}
	if cfg.Header == "" {
		cfg.Header = DefaultHeader
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 3 * time.Second}
	}
	return &Client{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"), tenant: cfg.Tenant,
		application: cfg.Application, header: cfg.Header, httpClient: cfg.HTTPClient,
	}, nil
}

func (c *Client) Authorize(ctx context.Context, apiKey, method, requestPath, host string) (Principal, error) {
	payload, err := json.Marshal(map[string]string{
		"tenant": c.tenant, "application": c.application, "method": method,
		"path": requestPath, "host": stripPort(host),
	})
	if err != nil {
		return Principal{}, fmt.Errorf("encode authorization request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/authorize", bytes.NewReader(payload))
	if err != nil {
		return Principal{}, fmt.Errorf("create authorization request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(c.header, apiKey)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return Principal{}, fmt.Errorf("authorize with Go Loose: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return Principal{}, fmt.Errorf("read authorization response: %w", err)
	}
	var result authorizationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return Principal{}, fmt.Errorf("decode authorization response (HTTP %d): %w", response.StatusCode, err)
	}
	if response.StatusCode != http.StatusOK || !result.Allowed {
		if result.Reason == "" {
			result.Reason = http.StatusText(response.StatusCode)
		}
		return Principal{}, fmt.Errorf("request denied by Go Loose: %s", result.Reason)
	}
	return result.Principal, nil
}

// Middleware rejects missing, invalid, or unverifiable keys and places the
// authorized Principal in the request context.
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := strings.TrimSpace(r.Header.Get(c.header))
		if apiKey == "" {
			writeMiddlewareError(w, http.StatusUnauthorized, "missing API key")
			return
		}
		principal, err := c.Authorize(r.Context(), apiKey, r.Method, r.URL.Path, r.Host)
		if err != nil {
			writeMiddlewareError(w, http.StatusForbidden, "API key not authorized")
			return
		}
		r.Header.Del(c.header)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, principal)))
	})
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(contextKey{}).(Principal)
	return principal, ok
}

func stripPort(host string) string {
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(parsed)
	}
	return strings.ToLower(host)
}

func writeMiddlewareError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
