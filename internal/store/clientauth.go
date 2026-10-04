package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/danyel/go-loose/internal/role"
)

type ManagedUser struct {
	ID             string   `json:"id"`
	TenantID       string   `json:"tenant_id"`
	Email          string   `json:"email"`
	DisplayName    string   `json:"display_name"`
	Role           string   `json:"role"`
	RoleID         string   `json:"role_id"`
	Permissions    []string `json:"permissions"`
	Status         string   `json:"status"`
	ApplicationIDs []string `json:"application_ids"`
	// AvatarKey is the stored locator. The server turns it into the absolute
	// AvatarURL returned to clients.
	AvatarKey *string `json:"-"`
	AvatarURL string  `json:"avatar_url"`
}

type ClientApplication struct {
	ID          string
	TenantID    string
	TenantSlug  string
	TenantName  string
	Application string
	Name        string
	ClientID    string
}

type ClientUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	DisplayName   string `json:"display_name"`
	TenantID      string `json:"tenant_id"`
	TenantSlug    string `json:"tenant_slug"`
	ApplicationID string `json:"application_id"`
	Application   string `json:"application"`
	// Role is the membership role in the tenant owning the application. A user
	// without a membership is reported as User so clients always see the least
	// privileged role.
	Role string `json:"role"`
	// Permissions is read from the role's own rows. A user without a membership
	// gets the permissions of the built-in User role.
	Permissions []string `json:"permissions"`
	// AvatarKey is the stored locator; the server expands it into AvatarURL.
	AvatarKey *string `json:"-"`
	AvatarURL string  `json:"avatar_url"`
}

func (s *Store) ListManagedUsers(ctx context.Context, administratorID string) ([]ManagedUser, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, m.tenant_id, u.email, u.display_name, r.slug, m.role_id,
		       CASE WHEN u.subject LIKE 'invited:%' THEN 'invited' ELSE 'active' END,
		       u.avatar_key,
		       COALESCE((
		           SELECT json_agg(rp.permission ORDER BY rp.permission)
		           FROM role_permissions rp WHERE rp.role_id = m.role_id
		       ), '[]'::json),
		       COALESCE((
		           SELECT json_agg(ua.application_id ORDER BY ua.application_id)
		           FROM user_application_access ua
		           JOIN applications a ON a.id = ua.application_id
		           WHERE ua.user_id = u.id AND a.tenant_id = m.tenant_id
		       ), '[]'::json)
		FROM users u
		JOIN memberships m ON m.user_id = u.id
		JOIN roles r ON r.id = m.role_id
		WHERE `+permissionPredicate("m.tenant_id", "$1", "$2")+`
		ORDER BY u.email, m.tenant_id`, administratorID, string(role.ManageUsers))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ManagedUser, 0)
	for rows.Next() {
		var user ManagedUser
		var permissions, applicationIDs []byte
		if err := rows.Scan(&user.ID, &user.TenantID, &user.Email, &user.DisplayName, &user.Role,
			&user.RoleID, &user.Status, &user.AvatarKey, &permissions, &applicationIDs); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(permissions, &user.Permissions); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(applicationIDs, &user.ApplicationIDs); err != nil {
			return nil, err
		}
		result = append(result, user)
	}
	return result, rows.Err()
}

// InviteUser adds a member to a tenant or, when the email already exists,
// re-invites them. The caller must hold users.manage in that tenant and may only
// hand out a role whose permissions they hold themselves.
func (s *Store) InviteUser(ctx context.Context, administratorID, tenantID, email, displayName, roleID string, passwordHash string) (ManagedUser, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ManagedUser{}, err
	}
	defer tx.Rollback()
	held, err := heldPermissions(ctx, tx, administratorID, tenantID)
	if err != nil {
		return ManagedUser{}, err
	}
	if !within([]string{string(role.ManageUsers)}, held) {
		return ManagedUser{}, ErrNotFound
	}
	resolved, err := resolveRoleID(ctx, tx, tenantID, roleID, held)
	if err != nil {
		return ManagedUser{}, err
	}
	var user ManagedUser
	err = tx.QueryRowContext(ctx, `
		INSERT INTO users(subject, email, display_name, password_hash, password_changed_at)
		VALUES ('invited:' || gen_random_uuid()::text, lower($1), $2, $3, now())
		ON CONFLICT ((lower(email))) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			password_hash = EXCLUDED.password_hash,
			password_changed_at = now()
		RETURNING id, email, display_name,
		          CASE WHEN subject LIKE 'invited:%' THEN 'invited' ELSE 'active' END`,
		email, displayName, passwordHash).Scan(&user.ID, &user.Email, &user.DisplayName, &user.Status)
	if err != nil {
		return ManagedUser{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO memberships(tenant_id, user_id, role_id) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET role_id = EXCLUDED.role_id`,
		tenantID, user.ID, resolved); err != nil {
		return ManagedUser{}, err
	}
	if err := tx.Commit(); err != nil {
		return ManagedUser{}, err
	}
	granted, err := roleGrants(ctx, s.db, resolved)
	if err != nil {
		return ManagedUser{}, err
	}
	user.TenantID, user.RoleID, user.ApplicationIDs = tenantID, resolved, []string{}
	if err := s.db.QueryRowContext(ctx, `SELECT slug FROM roles WHERE id = $1`, resolved).Scan(&user.Role); err != nil {
		return ManagedUser{}, err
	}
	user.Permissions = granted
	return user, nil
}

// SetUserAccess changes a member's role and replaces their application grants.
func (s *Store) SetUserAccess(ctx context.Context, administratorID, tenantID, userID, roleID string, applicationIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	held, err := heldPermissions(ctx, tx, administratorID, tenantID)
	if err != nil {
		return err
	}
	if !within([]string{string(role.ManageUsers)}, held) {
		return ErrNotFound
	}
	resolved, err := resolveRoleID(ctx, tx, tenantID, roleID, held)
	if err != nil {
		return err
	}
	if err := ensureTenantKeepsAnOwner(ctx, tx, tenantID, userID, resolved); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE memberships SET role_id = $3
		WHERE tenant_id = $1 AND user_id = $2 AND role_id IS DISTINCT FROM $3`,
		tenantID, userID, resolved)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		// Either the membership does not exist or the role is unchanged.
		var exists bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS(SELECT 1 FROM memberships WHERE tenant_id = $1 AND user_id = $2)`,
			tenantID, userID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM user_application_access ua
		USING applications a
		WHERE ua.application_id = a.id AND a.tenant_id = $1 AND ua.user_id = $2`,
		tenantID, userID); err != nil {
		return err
	}
	for _, applicationID := range applicationIDs {
		result, err := tx.ExecContext(ctx, `
			INSERT INTO user_application_access(application_id, user_id, granted_by)
			SELECT id, $2, $3 FROM applications WHERE id = $1 AND tenant_id = $4
			ON CONFLICT DO NOTHING`, applicationID, userID, administratorID, tenantID)
		if err != nil {
			return err
		}
		if count, _ := result.RowsAffected(); count == 0 {
			return ErrNotFound
		}
	}
	return tx.Commit()
}

// ErrLastOwner is returned when a change would leave a tenant without an owner.
var ErrLastOwner = errors.New("a tenant must keep at least one owner")

// ensureTenantKeepsAnOwner blocks demoting or moving away the only membership
// that still holds the owner role. Without this a tenant administrator could
// lock every administrator out of their own tenant with a single edit.
func ensureTenantKeepsAnOwner(ctx context.Context, tx *sql.Tx, tenantID, userID, newRoleID string) error {
	var losesOwner bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM memberships m
			JOIN roles r ON r.id = m.role_id
			WHERE m.tenant_id = $1 AND m.user_id = $2 AND r.slug = 'owner' AND m.role_id <> $3
		)`, tenantID, userID, newRoleID).Scan(&losesOwner); err != nil {
		return err
	}
	if !losesOwner {
		return nil
	}
	var remaining int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*)
		FROM memberships m
		JOIN roles r ON r.id = m.role_id
		WHERE m.tenant_id = $1 AND r.slug = 'owner' AND m.user_id <> $2`,
		tenantID, userID).Scan(&remaining); err != nil {
		return err
	}
	if remaining == 0 {
		return ErrLastOwner
	}
	return nil
}

func (s *Store) ConfigureClient(ctx context.Context, administratorID, applicationID string, redirectURIs []string, secretHash []byte) (Application, error) {
	var app Application
	var encoded []byte
	err := s.db.QueryRowContext(ctx, `
		UPDATE applications a
		SET redirect_uris = $4, client_secret_hash = $5, updated_at = now()
		WHERE a.id = $1 AND `+permissionPredicate("a.tenant_id", "$2", "$3")+`
		RETURNING a.id, a.client_id, to_json(a.redirect_uris), true`,
		applicationID, administratorID, string(role.ManageApplications), redirectURIs, secretHash).
		Scan(&app.ID, &app.ClientID, &encoded, &app.ClientReady)
	if errors.Is(err, sql.ErrNoRows) {
		return Application{}, ErrNotFound
	}
	if err == nil {
		err = json.Unmarshal(encoded, &app.RedirectURIs)
	}
	return app, err
}

func (s *Store) ClientForAuthorization(ctx context.Context, clientID, redirectURI, userID string) (ClientApplication, error) {
	var app ClientApplication
	err := s.db.QueryRowContext(ctx, `
		SELECT a.id, a.tenant_id, t.slug, t.name, a.slug, a.name, a.client_id
		FROM applications a
		JOIN tenants t ON t.id = a.tenant_id
		JOIN user_application_access ua ON ua.application_id = a.id AND ua.user_id = $3
		WHERE a.client_id = $1 AND $2 = ANY(a.redirect_uris)
		  AND a.client_secret_hash IS NOT NULL`,
		clientID, redirectURI, userID).
		Scan(&app.ID, &app.TenantID, &app.TenantSlug, &app.TenantName, &app.Application, &app.Name, &app.ClientID)
	if errors.Is(err, sql.ErrNoRows) {
		return ClientApplication{}, ErrNotFound
	}
	return app, err
}

func (s *Store) ValidateClientRedirect(ctx context.Context, clientID, redirectURI string) (ClientApplication, error) {
	var app ClientApplication
	err := s.db.QueryRowContext(ctx, `
		SELECT a.id, a.tenant_id, t.slug, t.name, a.slug, a.name, a.client_id
		FROM applications a
		JOIN tenants t ON t.id = a.tenant_id
		WHERE a.client_id = $1 AND $2 = ANY(a.redirect_uris)
		  AND a.client_secret_hash IS NOT NULL`,
		clientID, redirectURI).
		Scan(&app.ID, &app.TenantID, &app.TenantSlug, &app.TenantName, &app.Application, &app.Name, &app.ClientID)
	if errors.Is(err, sql.ErrNoRows) {
		return ClientApplication{}, ErrNotFound
	}
	return app, err
}

func (s *Store) ClientByID(ctx context.Context, clientID string) (ClientApplication, error) {
	var app ClientApplication
	err := s.db.QueryRowContext(ctx, `
		SELECT a.id, a.tenant_id, t.slug, t.name, a.slug, a.name, a.client_id
		FROM applications a
		JOIN tenants t ON t.id = a.tenant_id
		WHERE a.client_id = $1 AND a.client_secret_hash IS NOT NULL`,
		clientID).
		Scan(&app.ID, &app.TenantID, &app.TenantSlug, &app.TenantName, &app.Application, &app.Name, &app.ClientID)
	if errors.Is(err, sql.ErrNoRows) {
		return ClientApplication{}, ErrNotFound
	}
	return app, err
}

func (s *Store) CreateAuthorizationCode(ctx context.Context, applicationID, userID, redirectURI string, codeHash []byte) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO client_authorization_codes(code_hash, application_id, user_id, redirect_uri, expires_at)
		VALUES ($1, $2, $3, $4, now() + interval '2 minutes')`,
		codeHash, applicationID, userID, redirectURI)
	return err
}

func (s *Store) ExchangeAuthorizationCode(ctx context.Context, clientID, redirectURI string, secretHash, codeHash, tokenHash []byte) (ClientUser, time.Time, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ClientUser{}, time.Time{}, err
	}
	defer tx.Rollback()
	var user ClientUser
	var permissions []byte
	err = tx.QueryRowContext(ctx, `
		UPDATE client_authorization_codes c SET used_at = now()
		FROM applications a
		JOIN tenants t ON t.id = a.tenant_id
		JOIN user_application_access ua ON ua.application_id = a.id
		JOIN users u ON u.id = ua.user_id
		LEFT JOIN memberships m ON m.tenant_id = t.id AND m.user_id = u.id
		LEFT JOIN roles r ON r.id = m.role_id
		WHERE c.code_hash = $1 AND c.used_at IS NULL AND c.expires_at > now()
		  AND c.redirect_uri = $2 AND a.id = c.application_id
		  AND ua.user_id = c.user_id AND ua.application_id = a.id
		  AND a.client_id = $3 AND a.client_secret_hash = $4
		RETURNING u.id, u.email, u.display_name, t.id, t.slug, a.id, a.slug,
		          COALESCE(r.slug, 'user'), `+clientPermissions+`, u.avatar_key`,
		codeHash, redirectURI, clientID, secretHash).
		Scan(&user.ID, &user.Email, &user.DisplayName, &user.TenantID, &user.TenantSlug,
			&user.ApplicationID, &user.Application, &user.Role, &permissions, &user.AvatarKey)
	if errors.Is(err, sql.ErrNoRows) {
		return ClientUser{}, time.Time{}, ErrNotFound
	}
	if err != nil {
		return ClientUser{}, time.Time{}, err
	}
	if err := json.Unmarshal(permissions, &user.Permissions); err != nil {
		return ClientUser{}, time.Time{}, err
	}
	expiresAt := time.Now().UTC().Add(12 * time.Hour)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO client_user_sessions(token_hash, application_id, user_id, expires_at)
		VALUES ($1, $2, $3, $4)`, tokenHash, user.ApplicationID, user.ID, expiresAt); err != nil {
		return ClientUser{}, time.Time{}, err
	}
	return user, expiresAt, tx.Commit()
}

func (s *Store) ClientUserByToken(ctx context.Context, tokenHash []byte) (ClientUser, error) {
	var user ClientUser
	var permissions []byte
	err := s.db.QueryRowContext(ctx, `
		UPDATE client_user_sessions s SET last_used_at = now()
		FROM applications a
		JOIN tenants t ON t.id = a.tenant_id
		JOIN user_application_access ua ON ua.application_id = a.id
		JOIN users u ON u.id = ua.user_id
		LEFT JOIN memberships m ON m.tenant_id = t.id AND m.user_id = u.id
		LEFT JOIN roles r ON r.id = m.role_id
		WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
		  AND a.id = s.application_id AND ua.user_id = s.user_id
		RETURNING u.id, u.email, u.display_name, t.id, t.slug, a.id, a.slug,
		          COALESCE(r.slug, 'user'), `+clientPermissions+`, u.avatar_key`,
		tokenHash).
		Scan(&user.ID, &user.Email, &user.DisplayName, &user.TenantID, &user.TenantSlug,
			&user.ApplicationID, &user.Application, &user.Role, &permissions, &user.AvatarKey)
	if errors.Is(err, sql.ErrNoRows) {
		return ClientUser{}, ErrNotFound
	}
	if err != nil {
		return ClientUser{}, err
	}
	if err := json.Unmarshal(permissions, &user.Permissions); err != nil {
		return ClientUser{}, err
	}
	return user, nil
}

func (s *Store) RevokeClientSession(ctx context.Context, tokenHash []byte) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE client_user_sessions SET revoked_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL`, tokenHash)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}
