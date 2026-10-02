package store

import (
	"context"
	"database/sql"
	"errors"
)

func (s *Store) EnsurePasswordUser(ctx context.Context, email, displayName, passwordHash, tenantSlug, appSlug string) error {
	user, err := s.UpsertUser(ctx, "local:"+email, email, displayName)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET password_hash = $2, password_changed_at = now()
		WHERE id = $1 AND password_hash IS NULL`, user.ID, passwordHash); err != nil {
		return err
	}
	return s.Bootstrap(ctx, user.ID, tenantSlug, appSlug)
}

func (s *Store) PasswordUser(ctx context.Context, email string) (User, string, error) {
	var user User
	var passwordHash sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, display_name, password_hash
		FROM users
		WHERE lower(email) = lower($1)`, email).
		Scan(&user.ID, &user.Email, &user.DisplayName, &passwordHash)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !passwordHash.Valid) {
		return User{}, "", ErrNotFound
	}
	return user, passwordHash.String, err
}

func (s *Store) HasTenantAccess(ctx context.Context, userID, tenantSlug string) (bool, error) {
	var allowed bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1
			FROM memberships m
			JOIN tenants t ON t.id = m.tenant_id
			WHERE m.user_id = $1 AND t.slug = $2
		)`, userID, tenantSlug).Scan(&allowed)
	return allowed, err
}

func (s *Store) RecordLogin(ctx context.Context, userID *string, email, remoteAddress string, successful bool, reason string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_login_events(user_id, email, remote_address, successful, reason)
		VALUES ($1, lower($2), $3, $4, $5)`,
		userID, email, remoteAddress, successful, reason)
	return err
}
