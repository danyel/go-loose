package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Membership is one tenant role held by a user.
type Membership struct {
	TenantID    string   `json:"tenant_id"`
	TenantSlug  string   `json:"tenant_slug"`
	TenantName  string   `json:"tenant_name"`
	Role        string   `json:"role"`
	RoleID      string   `json:"role_id"`
	Permissions []string `json:"permissions"`
}

// Profile is a user's own account information. AvatarKey is the stored locator;
// the server expands it into an absolute AvatarURL.
type Profile struct {
	ID                    string       `json:"id"`
	Email                 string       `json:"email"`
	DisplayName           string       `json:"display_name"`
	AvatarKey             *string      `json:"-"`
	AvatarURL             string       `json:"avatar_url"`
	Memberships           []Membership `json:"memberships"`
	IsSystemAdministrator bool         `json:"is_system_administrator"`
	NameCustomized        bool         `json:"name_customized"`
	CreatedAt             time.Time    `json:"created_at"`
	LastLoginAt           time.Time    `json:"last_login_at"`
	ProfileUpdatedAt      *time.Time   `json:"profile_updated_at,omitempty"`
	AvatarUpdatedAt       *time.Time   `json:"avatar_updated_at,omitempty"`
}

// ProfileUpdate carries a self-service profile change. A nil DisplayName leaves
// the display name untouched. Avatar changes are mutually exclusive: Remove
// clears the picture, otherwise Data and ContentType replace it.
type ProfileUpdate struct {
	DisplayName  *string
	RemoveAvatar bool
	AvatarKey    string
	AvatarData   []byte
	ContentType  string
}

// Picture is a stored profile picture.
type Picture struct {
	Data        []byte
	ContentType string
	UpdatedAt   time.Time
}

// Profile loads a user together with every tenant role they hold.
func (s *Store) Profile(ctx context.Context, userID string) (Profile, error) {
	var profile Profile
	var avatarKey sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.email, u.display_name, u.avatar_key, u.name_customized,
		       u.created_at, u.last_login_at, u.profile_updated_at, u.avatar_updated_at,
		       EXISTS(SELECT 1 FROM system_administrators sa WHERE sa.user_id = u.id)
		FROM users u
		WHERE u.id = $1`, userID).
		Scan(&profile.ID, &profile.Email, &profile.DisplayName, &avatarKey, &profile.NameCustomized,
			&profile.CreatedAt, &profile.LastLoginAt, &profile.ProfileUpdatedAt,
			&profile.AvatarUpdatedAt, &profile.IsSystemAdministrator)
	if errors.Is(err, sql.ErrNoRows) {
		return Profile{}, ErrNotFound
	}
	if err != nil {
		return Profile{}, err
	}
	if avatarKey.Valid {
		profile.AvatarKey = &avatarKey.String
	}
	profile.Memberships = []Membership{}
	rows, err := s.db.QueryContext(ctx, `
		SELECT m.tenant_id, t.slug, t.name, r.slug, m.role_id,
		       COALESCE((
		           SELECT json_agg(rp.permission ORDER BY rp.permission)
		           FROM role_permissions rp WHERE rp.role_id = m.role_id
		       ), '[]'::json)
		FROM memberships m
		JOIN tenants t ON t.id = m.tenant_id
		JOIN roles r ON r.id = m.role_id
		WHERE m.user_id = $1
		ORDER BY t.name`, userID)
	if err != nil {
		return Profile{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item Membership
		var permissions []byte
		if err := rows.Scan(&item.TenantID, &item.TenantSlug, &item.TenantName, &item.Role,
			&item.RoleID, &permissions); err != nil {
			return Profile{}, err
		}
		if err := json.Unmarshal(permissions, &item.Permissions); err != nil {
			return Profile{}, err
		}
		profile.Memberships = append(profile.Memberships, item)
	}
	return profile, rows.Err()
}

// UpdateProfile applies a self-service profile change. The user is identified by
// their own id, so no membership check is required: every account may edit its
// own display name and picture regardless of role.
func (s *Store) UpdateProfile(ctx context.Context, userID string, update ProfileUpdate) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if update.DisplayName != nil {
		if _, err := tx.ExecContext(ctx, `
			UPDATE users
			SET display_name = $2, name_customized = true, profile_updated_at = now()
			WHERE id = $1`, userID, *update.DisplayName); err != nil {
			return err
		}
	}
	switch {
	case update.RemoveAvatar:
		if _, err := tx.ExecContext(ctx, `
			UPDATE users
			SET avatar = NULL, avatar_key = NULL, avatar_content_type = NULL,
			    avatar_updated_at = NULL, profile_updated_at = now()
			WHERE id = $1`, userID); err != nil {
			return err
		}
	case len(update.AvatarData) > 0:
		if _, err := tx.ExecContext(ctx, `
			UPDATE users
			SET avatar = $2, avatar_key = $3, avatar_content_type = $4,
			    avatar_updated_at = now(), profile_updated_at = now()
			WHERE id = $1`, userID, update.AvatarData, update.AvatarKey, update.ContentType); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Picture loads a stored profile picture by its unguessable key.
func (s *Store) Picture(ctx context.Context, key string) (Picture, error) {
	var picture Picture
	err := s.db.QueryRowContext(ctx, `
		SELECT avatar, avatar_content_type, avatar_updated_at
		FROM users
		WHERE avatar_key = $1 AND avatar IS NOT NULL`, key).
		Scan(&picture.Data, &picture.ContentType, &picture.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Picture{}, ErrNotFound
	}
	return picture, err
}
