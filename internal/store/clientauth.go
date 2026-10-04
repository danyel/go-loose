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
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	// AvatarKey is the stored locator; the server expands it into AvatarURL.
	AvatarKey *string `json:"-"`
	AvatarURL string  `json:"avatar_url"`
}

func (s *Store) ListManagedUsers(ctx context.Context, administratorID string) ([]ManagedUser, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, m.tenant_id, u.email, u.display_name, m.role,
		       CASE WHEN u.subject LIKE 'invited:%' THEN 'invited' ELSE 'active' END,
		       u.avatar_key,
		       COALESCE((
		           SELECT json_agg(ua.application_id ORDER BY ua.application_id)
		           FROM user_application_access ua
		           JOIN applications a ON a.id = ua.application_id
		           WHERE ua.user_id = u.id AND a.tenant_id = m.tenant_id
		       ), '[]'::json)
		FROM users u
		JOIN memberships m ON m.user_id = u.id
		WHERE EXISTS (
			SELECT 1 FROM memberships own
			WHERE own.tenant_id = m.tenant_id AND own.user_id = $1
			  AND own.role = ANY($2)
		)
		ORDER BY u.email, m.tenant_id`, administratorID, role.Grants(role.ManageUsers))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ManagedUser, 0)
	for rows.Next() {
		var user ManagedUser
		var applicationIDs []byte
		if err := rows.Scan(&user.ID, &user.TenantID, &user.Email, &user.DisplayName, &user.Role,
			&user.Status, &user.AvatarKey, &applicationIDs); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(applicationIDs, &user.ApplicationIDs); err != nil {
			return nil, err
		}
		user.Permissions = role.Role(user.Role).Permissions()
		result = append(result, user)
	}
	return result, rows.Err()
}

func (s *Store) InviteUser(ctx context.Context, administratorID, tenantID, email, displayName, membershipRole, passwordHash string) (ManagedUser, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ManagedUser{}, err
	}
	defer tx.Rollback()
	var permitted bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM memberships
			WHERE tenant_id = $1 AND user_id = $2 AND role = ANY($3)
		)`, tenantID, administratorID, role.Grants(role.ManageUsers)).Scan(&permitted); err != nil {
		return ManagedUser{}, err
	}
	if !permitted {
		return ManagedUser{}, ErrNotFound
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
		INSERT INTO memberships(tenant_id, user_id, role) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
		tenantID, user.ID, membershipRole); err != nil {
		return ManagedUser{}, err
	}
	if err := tx.Commit(); err != nil {
		return ManagedUser{}, err
	}
	user.TenantID, user.Role, user.ApplicationIDs = tenantID, membershipRole, []string{}
	user.Permissions = role.Role(membershipRole).Permissions()
	return user, nil
}

func (s *Store) SetUserAccess(ctx context.Context, administratorID, tenantID, userID, membershipRole string, applicationIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE memberships target SET role = $4
		FROM memberships administrator
		WHERE target.tenant_id = $1 AND target.user_id = $2
		  AND administrator.tenant_id = target.tenant_id
		  AND administrator.user_id = $3 AND administrator.role = ANY($5)`,
		tenantID, userID, administratorID, membershipRole, role.Grants(role.ManageUsers))
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
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

func (s *Store) ConfigureClient(ctx context.Context, administratorID, applicationID string, redirectURIs []string, secretHash []byte) (Application, error) {
	var app Application
	var encoded []byte
	err := s.db.QueryRowContext(ctx, `
		UPDATE applications a
		SET redirect_uris = $4, client_secret_hash = $5, updated_at = now()
		FROM memberships m
		WHERE a.id = $1 AND m.tenant_id = a.tenant_id AND m.user_id = $2
		  AND m.role = ANY($3)
		RETURNING a.id, a.client_id, to_json(a.redirect_uris), true`,
		applicationID, administratorID, role.Grants(role.ManageApplications), redirectURIs, secretHash).
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
	err = tx.QueryRowContext(ctx, `
		UPDATE client_authorization_codes c SET used_at = now()
		FROM applications a
		JOIN tenants t ON t.id = a.tenant_id
		JOIN user_application_access ua ON ua.application_id = a.id
		JOIN users u ON u.id = ua.user_id
		LEFT JOIN memberships m ON m.tenant_id = t.id AND m.user_id = u.id
		WHERE c.code_hash = $1 AND c.used_at IS NULL AND c.expires_at > now()
		  AND c.redirect_uri = $2 AND a.id = c.application_id
		  AND ua.user_id = c.user_id AND ua.application_id = a.id
		  AND a.client_id = $3 AND a.client_secret_hash = $4
		RETURNING u.id, u.email, u.display_name, t.id, t.slug, a.id, a.slug,
		          COALESCE(m.role, $5), u.avatar_key`,
		codeHash, redirectURI, clientID, secretHash, role.User).
		Scan(&user.ID, &user.Email, &user.DisplayName, &user.TenantID, &user.TenantSlug,
			&user.ApplicationID, &user.Application, &user.Role, &user.AvatarKey)
	if errors.Is(err, sql.ErrNoRows) {
		return ClientUser{}, time.Time{}, ErrNotFound
	}
	if err != nil {
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
	err := s.db.QueryRowContext(ctx, `
		UPDATE client_user_sessions s SET last_used_at = now()
		FROM applications a
		JOIN tenants t ON t.id = a.tenant_id
		JOIN user_application_access ua ON ua.application_id = a.id
		JOIN users u ON u.id = ua.user_id
		LEFT JOIN memberships m ON m.tenant_id = t.id AND m.user_id = u.id
		WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
		  AND a.id = s.application_id AND ua.user_id = s.user_id
		RETURNING u.id, u.email, u.display_name, t.id, t.slug, a.id, a.slug,
		          COALESCE(m.role, $2), u.avatar_key`,
		tokenHash, role.User).
		Scan(&user.ID, &user.Email, &user.DisplayName, &user.TenantID, &user.TenantSlug,
			&user.ApplicationID, &user.Application, &user.Role, &user.AvatarKey)
	if errors.Is(err, sql.ErrNoRows) {
		return ClientUser{}, ErrNotFound
	}
	return user, err
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
