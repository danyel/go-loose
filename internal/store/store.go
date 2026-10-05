package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/danyel/go-loose/internal/contract"
	"github.com/danyel/go-loose/internal/role"
)

var ErrNotFound = errors.New("not found")

// ErrTenantSlugTaken is returned when a tenant already uses the requested slug.
var ErrTenantSlugTaken = errors.New("tenant slug is already in use")

type Store struct {
	db *sql.DB
}

type User struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

type Tenant struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
	Role string `json:"role"`
	// Permissions is read from the role's own rows rather than from a Go matrix,
	// so a tenant that defines its own roles is described accurately.
	Permissions []string `json:"permissions"`
}

type Application struct {
	ID           string   `json:"id"`
	TenantID     string   `json:"tenant_id"`
	TenantSlug   string   `json:"tenant_slug,omitempty"`
	Slug         string   `json:"slug"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	AllowedHosts []string `json:"allowed_hosts"`
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
	ClientReady  bool     `json:"client_ready"`
}

type APIKey struct {
	ID            string     `json:"id"`
	ApplicationID string     `json:"application_id"`
	Name          string     `json:"name"`
	Prefix        string     `json:"prefix"`
	Status        string     `json:"status"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

type Contract struct {
	ID            string    `json:"id"`
	ApplicationID string    `json:"application_id"`
	Version       string    `json:"version"`
	SourceURL     *string   `json:"source_url,omitempty"`
	EndpointCount int       `json:"endpoint_count"`
	CreatedAt     time.Time `json:"created_at"`
}

type Authorization struct {
	Allowed    bool   `json:"allowed"`
	Reason     string `json:"reason,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	TenantSlug string `json:"tenant_slug,omitempty"`
	AppID      string `json:"application_id,omitempty"`
	AppSlug    string `json:"application_slug,omitempty"`
	APIKeyID   string `json:"api_key_id,omitempty"`
	APIKeyName string `json:"api_key_name,omitempty"`
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) UpsertUser(ctx context.Context, subject, email, displayName string) (User, error) {
	var user User
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	// The identity provider owns the display name until the user customizes it
	// in their profile. The row must still match on every login, otherwise the
	// insert below would collide with the unique email index.
	err = tx.QueryRowContext(ctx, `
		UPDATE users
		SET subject = $1,
		    email = lower($2),
		    display_name = CASE WHEN name_customized THEN display_name ELSE $3 END,
		    last_login_at = now()
		WHERE lower(email) = lower($2)
		RETURNING id, email, display_name`, subject, email, displayName).
		Scan(&user.ID, &user.Email, &user.DisplayName)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, `
			INSERT INTO users(subject, email, display_name)
			VALUES ($1, lower($2), $3)
			RETURNING id, email, display_name`, subject, email, displayName).
			Scan(&user.ID, &user.Email, &user.DisplayName)
	}
	if err != nil {
		return User{}, err
	}
	return user, tx.Commit()
}

func (s *Store) Bootstrap(ctx context.Context, userID, tenantSlug, appSlug string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var tenantID string
	err = tx.QueryRowContext(ctx, `
		INSERT INTO tenants(slug, name) VALUES ($1, $2)
		ON CONFLICT (slug) DO UPDATE SET name = tenants.name
		RETURNING id`, tenantSlug, title(tenantSlug)).Scan(&tenantID)
	if err != nil {
		return err
	}
	// Ownership is granted only while the tenant still has none. The condition is
	// about owners rather than about members: the installer's demonstration seed
	// creates tenants that already hold administrators, and refusing ownership
	// there would leave a local administrator bootstrapped afterwards with an
	// account that can never reach the console. A tenant that already has an owner
	// is still never taken over by a later bootstrap.
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO memberships(tenant_id, user_id, role_id)
		SELECT $1, $2, r.id
		FROM roles r
		WHERE r.slug = $3 AND r.tenant_id IS NULL
		  AND NOT EXISTS (
		      SELECT 1 FROM memberships m
		      JOIN roles held ON held.id = m.role_id
		      WHERE m.tenant_id = $1 AND held.slug = 'owner')
		ON CONFLICT DO NOTHING`, tenantID, userID, "owner"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO applications(tenant_id, slug, name, description)
		VALUES ($1, $2, $3, 'Bootstrap application')
		ON CONFLICT (tenant_id, slug) DO NOTHING`, tenantID, appSlug, title(appSlug)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO user_application_access(application_id, user_id, granted_by)
		SELECT a.id, $2, $2
		FROM applications a
		JOIN memberships m ON m.tenant_id = a.tenant_id AND m.user_id = $2
		WHERE a.tenant_id = $1 AND a.slug = $3
		ON CONFLICT DO NOTHING`, tenantID, userID, appSlug); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListTenants(ctx context.Context, userID string) ([]Tenant, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.id, t.slug, t.name, r.slug,
		       COALESCE((
		           SELECT json_agg(rp.permission ORDER BY rp.permission)
		           FROM role_permissions rp
		           WHERE rp.role_id = m.role_id
		       ), '[]'::json)
		FROM tenants t
		JOIN memberships m ON m.tenant_id = t.id
		JOIN roles r ON r.id = m.role_id
		WHERE m.user_id = $1
		ORDER BY t.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Tenant, 0)
	for rows.Next() {
		var item Tenant
		var permissions []byte
		if err := rows.Scan(&item.ID, &item.Slug, &item.Name, &item.Role, &permissions); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(permissions, &item.Permissions); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) CreateTenant(ctx context.Context, userID, slug, name string) (Tenant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Tenant{}, err
	}
	defer tx.Rollback()
	var tenant Tenant
	err = tx.QueryRowContext(ctx, `INSERT INTO tenants(slug, name) VALUES ($1, $2) RETURNING id, slug, name`, slug, name).
		Scan(&tenant.ID, &tenant.Slug, &tenant.Name)
	if isUniqueViolation(err) {
		// Reporting this as a generic failure would surface a 500 for what is an
		// ordinary mistake, and the console has no way to explain it.
		return Tenant{}, ErrTenantSlugTaken
	}
	if err != nil {
		return Tenant{}, err
	}
	// Whoever creates a tenant owns it.
	var permissions []byte
	err = tx.QueryRowContext(ctx, `
		INSERT INTO memberships(tenant_id, user_id, role_id)
		SELECT $1, $2, r.id FROM roles r
		WHERE r.slug = 'owner' AND r.tenant_id IS NULL
		RETURNING (SELECT slug FROM roles WHERE slug = 'owner' AND tenant_id IS NULL),
		          COALESCE((
		              SELECT json_agg(rp.permission ORDER BY rp.permission)
		              FROM role_permissions rp
		              JOIN roles granted ON granted.id = rp.role_id
		              WHERE granted.slug = 'owner' AND granted.tenant_id IS NULL
		          ), '[]'::json)`,
		tenant.ID, userID).Scan(&tenant.Role, &permissions)
	if err != nil {
		return Tenant{}, err
	}
	if err := json.Unmarshal(permissions, &tenant.Permissions); err != nil {
		return Tenant{}, err
	}
	if err := tx.Commit(); err != nil {
		return Tenant{}, err
	}
	return tenant, nil
}

func (s *Store) ListApplications(ctx context.Context, userID string) ([]Application, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.tenant_id, t.slug, a.slug, a.name, a.description,
		       to_json(a.allowed_hosts), a.client_id, to_json(a.redirect_uris),
		       (a.client_secret_hash IS NOT NULL)
		FROM applications a
		JOIN tenants t ON t.id = a.tenant_id
		JOIN memberships m ON m.tenant_id = a.tenant_id
		WHERE m.user_id = $1
		ORDER BY t.slug, a.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Application, 0)
	for rows.Next() {
		var item Application
		var allowedHosts, redirectURIs []byte
		if err := rows.Scan(&item.ID, &item.TenantID, &item.TenantSlug, &item.Slug, &item.Name, &item.Description, &allowedHosts, &item.ClientID, &redirectURIs, &item.ClientReady); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(allowedHosts, &item.AllowedHosts); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(redirectURIs, &item.RedirectURIs); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) CreateApplication(ctx context.Context, userID string, app Application) (Application, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO applications(tenant_id, slug, name, description, allowed_hosts)
		SELECT $1, $2, $3, $4, $5
		WHERE `+permissionPredicate("$1", "$6", "$7")+`
		RETURNING id, tenant_id, slug, name, description, to_json(allowed_hosts),
		          client_id, to_json(redirect_uris), false`,
		app.TenantID, app.Slug, app.Name, app.Description, app.AllowedHosts, userID,
		string(role.ManageApplications))
	var allowedHosts, redirectURIs []byte
	err := row.Scan(&app.ID, &app.TenantID, &app.Slug, &app.Name, &app.Description, &allowedHosts, &app.ClientID, &redirectURIs, &app.ClientReady)
	if errors.Is(err, sql.ErrNoRows) {
		return Application{}, ErrNotFound
	}
	if err == nil {
		err = json.Unmarshal(allowedHosts, &app.AllowedHosts)
	}
	if err == nil {
		err = json.Unmarshal(redirectURIs, &app.RedirectURIs)
	}
	return app, err
}

func (s *Store) ListAPIKeys(ctx context.Context, userID string) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT k.id, k.application_id, k.name, k.prefix, k.status, k.expires_at, k.last_used_at, k.created_at
		FROM api_keys k
		JOIN memberships m ON m.tenant_id = k.tenant_id
		WHERE m.user_id = $1
		ORDER BY k.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]APIKey, 0)
	for rows.Next() {
		var item APIKey
		if err := rows.Scan(&item.ID, &item.ApplicationID, &item.Name, &item.Prefix, &item.Status, &item.ExpiresAt, &item.LastUsedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) CreateAPIKey(ctx context.Context, userID, applicationID, name, prefix string, hash []byte, expiresAt *time.Time) (APIKey, error) {
	var item APIKey
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO api_keys(tenant_id, application_id, name, prefix, secret_hash, expires_at, created_by)
		SELECT a.tenant_id, a.id, $2, $3, $4, $5, $6
		FROM applications a
		WHERE a.id = $1 AND `+permissionPredicate("a.tenant_id", "$6", "$7")+`
		RETURNING id, application_id, name, prefix, status, expires_at, last_used_at, created_at`,
		applicationID, name, prefix, hash, expiresAt, userID, string(role.ManageKeys)).
		Scan(&item.ID, &item.ApplicationID, &item.Name, &item.Prefix, &item.Status, &item.ExpiresAt, &item.LastUsedAt, &item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return APIKey{}, ErrNotFound
	}
	return item, err
}

func (s *Store) RevokeAPIKey(ctx context.Context, userID, keyID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE api_keys k SET status = 'revoked', revoked_at = now()
		WHERE k.id = $1 AND `+permissionPredicate("k.tenant_id", "$2", "$3"),
		keyID, userID, string(role.ManageKeys))
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Authorize(ctx context.Context, hash []byte, tenantSlug, appSlug, method, path, host string) (Authorization, error) {
	var auth Authorization
	err := s.db.QueryRowContext(ctx, `
		SELECT t.id, t.slug, a.id, a.slug, k.id, k.name,
			(k.status = 'active' AND (k.expires_at IS NULL OR k.expires_at > now())
			 AND ($2 = '' OR t.slug = $2) AND ($3 = '' OR a.slug = $3)
			 AND (cardinality(a.allowed_hosts) = 0 OR $4 = ANY(a.allowed_hosts))) AS allowed
		FROM api_keys k
		JOIN applications a ON a.id = k.application_id
		JOIN tenants t ON t.id = k.tenant_id
		WHERE k.secret_hash = $1`,
		hash, tenantSlug, appSlug, host).
		Scan(&auth.TenantID, &auth.TenantSlug, &auth.AppID, &auth.AppSlug, &auth.APIKeyID, &auth.APIKeyName, &auth.Allowed)
	if errors.Is(err, sql.ErrNoRows) {
		auth.Reason = "invalid_api_key"
		s.recordAuthorization(ctx, auth, method, path, host)
		return auth, nil
	}
	if err != nil {
		return Authorization{}, err
	}
	if auth.Allowed {
		auth.Reason = "authorized"
		_, _ = s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = now() WHERE id = $1`, auth.APIKeyID)
	} else {
		auth.Reason = "key_scope_mismatch_or_inactive"
	}
	s.recordAuthorization(ctx, auth, method, path, host)
	return auth, nil
}

func (s *Store) recordAuthorization(ctx context.Context, auth Authorization, method, path, host string) {
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO authorization_events(tenant_id, application_id, api_key_id, method, path, host, allowed, reason)
		VALUES (NULLIF($1, '')::uuid, NULLIF($2, '')::uuid, NULLIF($3, '')::uuid, $4, $5, $6, $7, $8)`,
		auth.TenantID, auth.AppID, auth.APIKeyID, method, path, host, auth.Allowed, auth.Reason)
}

func (s *Store) SaveContract(ctx context.Context, userID, applicationID string, document contract.Document, sourceURL *string) (Contract, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Contract{}, err
	}
	defer tx.Rollback()
	var result Contract
	err = tx.QueryRowContext(ctx, `
		INSERT INTO openapi_contracts(application_id, version, source_url, document, created_by)
		SELECT a.id, $2, $3, $4, $5
		FROM applications a
		WHERE a.id = $1 AND `+permissionPredicate("a.tenant_id", "$5", "$6")+`
		RETURNING id, application_id, version, source_url, created_at`,
		applicationID, document.Version, sourceURL, document.JSON, userID,
		string(role.ManageContracts)).
		Scan(&result.ID, &result.ApplicationID, &result.Version, &result.SourceURL, &result.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Contract{}, ErrNotFound
	}
	if err != nil {
		return Contract{}, err
	}
	for _, endpoint := range document.Endpoints {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO contract_endpoints(contract_id, method, path, operation_id) VALUES ($1, $2, $3, $4)`,
			result.ID, endpoint.Method, endpoint.Path, endpoint.OperationID); err != nil {
			return Contract{}, err
		}
	}
	result.EndpointCount = len(document.Endpoints)
	if err := tx.Commit(); err != nil {
		return Contract{}, err
	}
	return result, nil
}

func (s *Store) ListContracts(ctx context.Context, userID string) ([]Contract, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.id, c.application_id, c.version, c.source_url, count(e.id), c.created_at
		FROM openapi_contracts c
		JOIN applications a ON a.id = c.application_id
		JOIN memberships m ON m.tenant_id = a.tenant_id
		LEFT JOIN contract_endpoints e ON e.contract_id = c.id
		WHERE m.user_id = $1
		GROUP BY c.id
		ORDER BY c.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Contract, 0)
	for rows.Next() {
		var item Contract
		if err := rows.Scan(&item.ID, &item.ApplicationID, &item.Version, &item.SourceURL, &item.EndpointCount, &item.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func title(slug string) string {
	parts := strings.FieldsFunc(slug, func(r rune) bool { return r == '-' || r == '_' })
	for index := range parts {
		if parts[index] != "" {
			parts[index] = strings.ToUpper(parts[index][:1]) + parts[index][1:]
		}
	}
	return strings.Join(parts, " ")
}

func Wrap(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
