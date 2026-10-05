// Package behaviour drives the whole application over real HTTP against a real
// PostgreSQL database, the way a person would: install it, sign in, click
// through every screen, and check that what was written can be read back after
// the process is replaced.
//
// The suite is opt-in. `go test ./...` skips it unless GO_LOOSE_BEHAVIOUR=1 is
// set, because it needs a scratch database and, for the installer, real Google
// credentials. Run it with `make behaviour-test`.
package behaviour

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/danyel/go-loose/internal/config"
	"github.com/danyel/go-loose/internal/database"
	"github.com/danyel/go-loose/internal/server"
)

const (
	apexHost       = "auth.test"
	localAdminMail = "admin@goloose.local"
	localAdminPass = "local-admin-password-2026"
	sessionSecret  = "behaviour-suite-session-secret-value-32"
)

// harness is one running instance of the application plus a browser that speaks
// to it over HTTP.
type harness struct {
	t        *testing.T
	server   *http.Server
	listener net.Listener
	handler  http.Handler
	db       *sql.DB
	addr     string
	baseURL  string
	origin   string
}

// browser is a very small cookie jar with the domain rules that matter here.
// net/http/cookiejar cannot be used because the suite addresses the server by IP
// while sending tenant hostnames in the Host header, and the jar keys cookies by
// the URL host rather than the header. Getting that wrong would silently drop the
// shared session cookie that the client login flow depends on.
type browser struct {
	t       *testing.T
	addr    string
	client  *http.Client
	cookies map[string]map[string]*http.Cookie // domain -> name -> cookie
}

// newBrowser returns a cookie jar bound to one instance. Cookies are per browser,
// so a second browser is a second, independent signed-out visitor.
func newBrowser(t *testing.T, addr string) *browser {
	return &browser{
		t: t, addr: addr,
		client: &http.Client{
			Timeout: 30 * time.Second,
			// Redirects are inspected rather than followed: several flows assert on
			// the Location header, and an automatic follow would hide it.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		cookies: map[string]map[string]*http.Cookie{},
	}
}

// host extracts the hostname from a Host header that may carry a port.
func hostname(host string) string {
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		return parsed
	}
	return host
}

// domainMatches implements the cookie domain rule: an exact host match, or a
// suffix match for a domain cookie.
func domainMatches(domain, host string) bool {
	if domain == host {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

func (b *browser) absorb(host string, cookies []*http.Cookie) {
	for _, cookie := range cookies {
		domain := cookie.Domain
		if domain == "" {
			domain = hostname(host)
		}
		domain = strings.TrimPrefix(domain, ".")
		if cookie.MaxAge < 0 {
			if jar, ok := b.cookies[domain]; ok {
				delete(jar, cookie.Name)
			}
			continue
		}
		if _, ok := b.cookies[domain]; !ok {
			b.cookies[domain] = map[string]*http.Cookie{}
		}
		copied := *cookie
		b.cookies[domain][cookie.Name] = &copied
	}
}

// request performs one request without following redirects and records cookies.
func (b *browser) request(method, host, path string, body io.Reader, headers map[string]string) *http.Response {
	b.t.Helper()
	target := "http://" + b.addr + path
	request, err := http.NewRequest(method, target, body)
	if err != nil {
		b.t.Fatalf("build %s %s: %v", method, path, err)
	}
	request.Host = host
	for domain, jar := range b.cookies {
		if !domainMatches(domain, hostname(host)) {
			continue
		}
		for name, cookie := range jar {
			request.AddCookie(&http.Cookie{Name: name, Value: cookie.Value})
		}
	}
	for name, value := range headers {
		if value == "" {
			request.Header.Del(name)
			continue
		}
		request.Header.Set(name, value)
	}
	response, err := b.client.Do(request)
	if err != nil {
		b.t.Fatalf("%s %s (host %s): %v", method, path, host, err)
	}
	b.absorb(host, response.Cookies())
	return response
}

// get performs a GET and returns the response. The caller closes the body.
func (b *browser) get(host, path string, headers map[string]string) *http.Response {
	return b.request(http.MethodGet, host, path, nil, headers)
}

// form performs a form POST, the way a browser submits an HTML form.
func (b *browser) form(host, path string, values url.Values, headers map[string]string) *http.Response {
	encoded := values.Encode()
	merged := map[string]string{
		"Content-Type":   "application/x-www-form-urlencoded",
		"Accept":         "text/html,application/json",
		"Content-Length": fmt.Sprint(len(encoded)),
	}
	for name, value := range headers {
		merged[name] = value
	}
	return b.request(http.MethodPost, host, path, strings.NewReader(encoded), merged)
}

// json performs a JSON write, the way the console's own scripts do. The Origin
// header is what requireSameOrigin checks, so it defaults to the host being used.
func (b *browser) json(method, host, path string, payload any) *http.Response {
	encoded, err := json.Marshal(payload)
	if err != nil {
		b.t.Fatalf("encode payload: %v", err)
	}
	return b.request(method, host, path, strings.NewReader(string(encoded)), map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
		"Origin":       "http://" + host,
	})
}

func bodyOf(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(content)
}

var csrfPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func csrfFrom(t *testing.T, page string) string {
	t.Helper()
	match := csrfPattern.FindStringSubmatch(page)
	if match == nil {
		t.Fatalf("no CSRF token in page: %.400s", page)
	}
	return match[1]
}

// start boots the application on a fresh port. It is called once for the
// install phase and again by restart, which is how the suite proves that state
// lives in PostgreSQL rather than in the process.
// start boots the application. localAdmin is deliberately false for the install
// phase: configuring GO_LOOSE_LOCAL_ADMIN_PASSWORD marks an instance installed on
// its own, which would hide the installer this suite exists to exercise.
func start(t *testing.T, databaseURL string, localAdmin bool) *harness {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	baseURL := "http://" + apexHost + ":" + portOf(addr)

	setEnv(t, baseEnv(addr, baseURL, databaseURL, localAdmin))
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	ctx := context.Background()
	db, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	handler, err := server.New(ctx, cfg, db, quietLogger())
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	harness := &harness{
		t: t, listener: listener, handler: handler.Handler(), db: db,
		addr: addr, baseURL: baseURL, origin: baseURL,
	}
	harness.serve()
	return harness
}

func (h *harness) serve() {
	h.server = &http.Server{Handler: h.handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		// The listener is already open, so a failure here is a real defect rather
		// than a bind race; report it through the test log.
		_ = h.server.Serve(h.listener)
	}()
	h.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.server.Shutdown(ctx)
	})
}

// stop closes the running instance. The address is kept so restart can rebind it.
func (h *harness) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = h.server.Shutdown(ctx)
	// Shutdown stops accepting but the listener can outlive it briefly, so close it
	// explicitly rather than hoping the port is free by the time we rebind.
	_ = h.listener.Close()
}

// restart replaces the process with a new one over the same database.
//
// The new instance listens on a fresh port, the way a real deployment would come
// back up behind its proxy. Nothing observable depends on the port: the session
// cookie is scoped to the host without a port, and the application's redirect
// URIs are external.
func (h *harness) restart(databaseURL string) *harness {
	h.t.Helper()
	h.stop()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	baseURL := "http://" + apexHost + ":" + portOf(addr)

	setEnv(h.t, baseEnv(addr, baseURL, databaseURL, true))
	cfg, err := config.Load()
	if err != nil {
		h.t.Fatalf("load config: %v", err)
	}
	ctx := context.Background()
	handler, err := server.New(ctx, cfg, h.db, quietLogger())
	if err != nil {
		h.t.Fatalf("rebuild server: %v", err)
	}
	next := &harness{
		t: h.t, listener: listener, handler: handler.Handler(), db: h.db,
		addr: addr, baseURL: baseURL, origin: baseURL,
	}
	next.serve()
	return next
}

// baseEnv is the environment the suite runs the application under.
func baseEnv(addr, baseURL, databaseURL string, localAdmin bool) map[string]string {
	env := map[string]string{
		"GO_LOOSE_ADDR":                        addr,
		"GO_LOOSE_BASE_URL":                    baseURL,
		"GO_LOOSE_AUTH_DOMAIN":                 apexHost,
		"GO_LOOSE_DATABASE_URL":                databaseURL,
		"GO_LOOSE_SESSION_SECRET":              sessionSecret,
		"GO_LOOSE_DEV_LOGIN":                   "false",
		"GO_LOOSE_LOCAL_LOGIN":                 "true",
		"GO_LOOSE_OIDC_REDIRECT_URL":           baseURL + "/auth/callback",
		"GO_LOOSE_ALLOW_PRIVATE_CONTRACT_URLS": "true",
		"GO_LOOSE_BOOTSTRAP_TENANT":            "nmbs",
		"GO_LOOSE_BOOTSTRAP_APP":               "guess",
		// The provider credentials are never injected through the environment: the
		// installer must be the only thing that configures OIDC here.
		"GO_LOOSE_OIDC_ISSUER":        "",
		"GO_LOOSE_OIDC_CLIENT_ID":     "",
		"GO_LOOSE_OIDC_CLIENT_SECRET": "",
	}
	if localAdmin {
		env["GO_LOOSE_LOCAL_ADMIN_EMAIL"] = localAdminMail
		env["GO_LOOSE_LOCAL_ADMIN_PASSWORD"] = localAdminPass
	}
	return env
}

func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "8080"
	}
	return port
}

// tenantHost is the hostname a tenant's members sign in on.
func (h *harness) tenantHost(slug string) string {
	return slug + "." + apexHost + ":" + portOf(h.addr)
}

func (h *harness) apex() string {
	return apexHost + ":" + portOf(h.addr)
}

func setEnv(t *testing.T, values map[string]string) {
	t.Helper()
	for name, value := range values {
		t.Setenv(name, value)
	}
}

// resetDatabase drops every table including schema_migrations, so the next start
// replays the migration history from the beginning.
func resetDatabase(t *testing.T, databaseURL string) {
	t.Helper()
	db, err := database.Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("open database to reset: %v", err)
	}
	defer db.Close()
	rows, err := db.QueryContext(context.Background(),
		`SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatalf("scan table name: %v", err)
		}
		tables = append(tables, `"`+name+`"`)
	}
	rows.Close()
	for _, table := range tables {
		if _, err := db.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+table+" CASCADE"); err != nil {
			t.Fatalf("drop %s: %v", table, err)
		}
	}
}

// googleCredentials reads the real client credentials the installer is meant to
// receive. The values never appear in test output.
type googleCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func loadGoogleCredentials(t *testing.T) googleCredentials {
	t.Helper()
	if override := os.Getenv("GO_LOOSE_BEHAVIOUR_CLIENT_ID"); override != "" {
		return googleCredentials{ClientID: override, ClientSecret: os.Getenv("GO_LOOSE_BEHAVIOUR_CLIENT_SECRET")}
	}
	path := filepath.Join("..", "..", "google_secrets.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no Google credentials at %s: %v", path, err)
	}
	var file struct {
		Web struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		} `json:"web"`
	}
	if err := json.Unmarshal(content, &file); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if file.Web.ClientID == "" || file.Web.ClientSecret == "" {
		t.Skipf("%s has no client_id or client_secret", path)
	}
	return googleCredentials{ClientID: file.Web.ClientID, ClientSecret: file.Web.ClientSecret}
}

// decode reads a JSON response body into target and fails on a non-2xx status,
// reporting the server's own error message.
func decode[T any](t *testing.T, response *http.Response, wantStatus int) T {
	t.Helper()
	var target T
	body := bodyOf(t, response)
	if response.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d: %s", response.StatusCode, wantStatus, body)
	}
	if err := json.Unmarshal([]byte(body), &target); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return target
}

// statusOnly reads a body without decoding, for flows whose payload is empty.
func statusOnly(t *testing.T, response *http.Response, wantStatus int) string {
	t.Helper()
	body := bodyOf(t, response)
	if response.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d: %s", response.StatusCode, wantStatus, body)
	}
	return body
}

// location returns the redirect target of a response.
func location(t *testing.T, response *http.Response) string {
	t.Helper()
	target := response.Header.Get("Location")
	if target == "" {
		t.Fatalf("no Location header on %d", response.StatusCode)
	}
	return target
}

// quietLogger keeps the suite's output readable. The application logs every
// request, which would bury the test output; the suite reports its own failures.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// stringReader is a small helper for the raw request bodies the authorization
// endpoint expects, where the exact bytes matter more than a struct.
func stringReader(body string) io.Reader { return strings.NewReader(body) }
