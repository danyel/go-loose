package store

import (
	"context"
	"database/sql"
	"errors"
)

type Installation struct {
	OIDCIssuer           string
	OIDCClientID         string
	OIDCSecretCiphertext []byte
	SeededDemo           bool
}

type DemoUser struct {
	Email        string
	DisplayName  string
	PasswordHash string
	TenantSlug   string
}

func (s *Store) Installation(ctx context.Context) (Installation, error) {
	var installation Installation
	err := s.db.QueryRowContext(ctx, `
		SELECT oidc_issuer, oidc_client_id, oidc_client_secret_ciphertext, seeded_demo
		FROM installation_settings WHERE singleton = true`).
		Scan(&installation.OIDCIssuer, &installation.OIDCClientID, &installation.OIDCSecretCiphertext, &installation.SeededDemo)
	if errors.Is(err, sql.ErrNoRows) {
		return Installation{}, ErrNotFound
	}
	return installation, err
}

func (s *Store) Install(ctx context.Context, installation Installation, demoUsers []DemoUser) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO installation_settings(singleton, oidc_issuer, oidc_client_id, oidc_client_secret_ciphertext, seeded_demo)
		VALUES (true, $1, $2, $3, $4)`,
		installation.OIDCIssuer, installation.OIDCClientID, installation.OIDCSecretCiphertext, installation.SeededDemo); err != nil {
		return err
	}
	if len(demoUsers) == 0 {
		return tx.Commit()
	}
	for _, tenantSlug := range []string{"nmbs", "ypto"} {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tenants(slug, name) VALUES ($1, upper($1))
			ON CONFLICT (slug) DO NOTHING`, tenantSlug); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO applications(tenant_id, slug, name, description)
			SELECT id, 'guess', 'Guess', 'Seeded Guess interview application'
			FROM tenants WHERE slug = $1
			ON CONFLICT (tenant_id, slug) DO NOTHING`, tenantSlug); err != nil {
			return err
		}
	}
	for _, demo := range demoUsers {
		var userID string
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO users(subject, email, display_name, password_hash, password_changed_at)
			VALUES ('demo:' || lower($1), lower($1), $2, $3, now())
			ON CONFLICT ((lower(email))) DO UPDATE SET
				display_name = EXCLUDED.display_name,
				password_hash = EXCLUDED.password_hash,
				password_changed_at = now()
			RETURNING id`, demo.Email, demo.DisplayName, demo.PasswordHash).Scan(&userID); err != nil {
			return err
		}
		var tenantID string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM tenants WHERE slug = $1`, demo.TenantSlug).Scan(&tenantID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO memberships(tenant_id, user_id, role) VALUES ($1, $2, 'admin')
			ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = 'admin'`, tenantID, userID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO user_application_access(application_id, user_id, granted_by)
			SELECT id, $2, $2 FROM applications WHERE tenant_id = $1 AND slug = 'guess'
			ON CONFLICT DO NOTHING`, tenantID, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ClaimFirstSystemAdministrator(ctx context.Context, userID string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(554628171917)`); err != nil {
		return false, err
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM system_administrators)`).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO system_administrators(user_id) VALUES ($1)`, userID); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO memberships(tenant_id, user_id, role)
		SELECT id, $1, 'owner' FROM tenants ON CONFLICT DO NOTHING`, userID); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_application_access(application_id, user_id, granted_by)
		SELECT id, $1, $1 FROM applications ON CONFLICT DO NOTHING`, userID); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (s *Store) HasManagementAccess(ctx context.Context, userID string) (bool, error) {
	var allowed bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM system_administrators WHERE user_id = $1)
		    OR EXISTS(SELECT 1 FROM memberships WHERE user_id = $1)`, userID).Scan(&allowed)
	return allowed, err
}

func (s *Store) IsSystemAdministrator(ctx context.Context, userID string) (bool, error) {
	var allowed bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM system_administrators WHERE user_id = $1)`, userID).Scan(&allowed)
	return allowed, err
}

func (s *Store) ListPendingUsers(ctx context.Context, administratorID string) ([]User, error) {
	isAdministrator, err := s.IsSystemAdministrator(ctx, administratorID)
	if err != nil {
		return nil, err
	}
	if !isAdministrator {
		return []User{}, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.email, u.display_name
		FROM users u
		WHERE NOT EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = u.id)
		  AND NOT EXISTS (SELECT 1 FROM system_administrators sa WHERE sa.user_id = u.id)
		ORDER BY u.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]User, 0)
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Email, &user.DisplayName); err != nil {
			return nil, err
		}
		result = append(result, user)
	}
	return result, rows.Err()
}

func (s *Store) ApprovePendingUser(ctx context.Context, administratorID, tenantID, userID, role string, applicationIDs []string) error {
	isAdministrator, err := s.IsSystemAdministrator(ctx, administratorID)
	if err != nil {
		return err
	}
	if !isAdministrator {
		return ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		INSERT INTO memberships(tenant_id, user_id, role)
		SELECT $1, id, $3 FROM users WHERE id = $2
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
		tenantID, userID, role)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
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
