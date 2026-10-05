package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/danyel/go-loose/internal/role"
)

// Permission is one entry in the installation-wide catalog. The nine seeded by
// migration 0007 are the capabilities the console enforces; anything added later
// is grantable and reported to client applications but is not checked here,
// because nothing in the request path tests for it.
type Permission struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
	System      bool   `json:"system"`
	// RoleCount is how many roles currently grant it. A permission that no role
	// grants can be removed again.
	RoleCount int `json:"role_count"`
	// Enforced reports whether the application itself checks for this
	// permission. The console surfaces this so an operator is not misled into
	// believing a custom capability is enforced.
	Enforced bool `json:"enforced"`
}

var (
	// ErrPermissionInUse is returned when a permission a role still grants is
	// deleted.
	ErrPermissionInUse = errors.New("permission is still granted by a role")
	// ErrPermissionTaken is returned when a permission name already exists.
	ErrPermissionTaken = errors.New("permission name is already in use")
	// ErrPermissionSystem is returned when a built-in permission would be edited
	// or deleted.
	ErrPermissionSystem = errors.New("built-in permissions cannot be changed")
)

// permissionName constrains a name to lowercase dotted words such as
// "reports.export". The database enforces the same shape.
var permissionName = regexp.MustCompile(`^[a-z0-9][a-z0-9]*(?:[.-][a-z0-9]+)*$`)

// ValidPermissionName reports whether a name is well formed.
func ValidPermissionName(name string) bool {
	return len(name) >= 3 && len(name) <= 100 && permissionName.MatchString(name)
}

// ListPermissions returns the whole catalog, most sensitive first for the
// built-ins and alphabetically after them.
func (s *Store) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.name, p.label, p.description, p.is_system,
		       (SELECT count(*) FROM role_permissions rp WHERE rp.permission = p.name)
		FROM permissions p
		ORDER BY array_position(`+permissionOrder+`, p.name) NULLS LAST, p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Permission, 0)
	for rows.Next() {
		var item Permission
		if err := rows.Scan(&item.Name, &item.Label, &item.Description, &item.System, &item.RoleCount); err != nil {
			return nil, err
		}
		item.Enforced = role.Permission(item.Name).Valid()
		result = append(result, item)
	}
	return result, rows.Err()
}

// CreatePermission adds a name to the catalog so that roles can grant it.
// Requires either a system administrator or tenants.manage, because the catalog
// is shared by every tenant rather than scoped to one.
func (s *Store) CreatePermission(ctx context.Context, actorID, name, label, description string) (Permission, error) {
	name = strings.TrimSpace(name)
	label = strings.TrimSpace(label)
	description = strings.TrimSpace(description)
	if !ValidPermissionName(name) {
		return Permission{}, fmt.Errorf("%w: use lowercase words separated by dots", ErrUnknownPermission)
	}
	if label == "" || len(label) > 100 {
		return Permission{}, fmt.Errorf("%w: label must be between 1 and 100 characters", ErrUnknownPermission)
	}
	if len(description) > 500 {
		return Permission{}, fmt.Errorf("%w: description must be 500 characters or fewer", ErrUnknownPermission)
	}
	if role.Permission(name).Valid() {
		// The name is one the application enforces; it is already seeded, so this
		// can only be a duplicate.
		return Permission{}, ErrPermissionTaken
	}
	permitted, err := s.mayAdministerCatalog(ctx, actorID)
	if err != nil {
		return Permission{}, err
	}
	if !permitted {
		return Permission{}, ErrNotFound
	}
	item := Permission{Name: name, Label: label, Description: description, Enforced: false}
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO permissions(name, label, description)
		VALUES ($1, $2, $3)
		RETURNING name, label, description, is_system,
		          (SELECT count(*) FROM role_permissions rp WHERE rp.permission = permissions.name)`,
		name, label, description).
		Scan(&item.Name, &item.Label, &item.Description, &item.System, &item.RoleCount)
	if isUniqueViolation(err) {
		return Permission{}, ErrPermissionTaken
	}
	if err != nil {
		return Permission{}, err
	}
	return item, nil
}

// DeletePermission removes a catalog entry that no role grants. Built-in
// permissions are kept: the console enforces them and dropping one would leave a
// membership holding a capability nothing recognizes.
func (s *Store) DeletePermission(ctx context.Context, actorID, name string) error {
	permitted, err := s.mayAdministerCatalog(ctx, actorID)
	if err != nil {
		return err
	}
	if !permitted {
		return ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var (
		label  string
		system bool
		grants int
	)
	err = tx.QueryRowContext(ctx, `
		SELECT label, is_system,
		       (SELECT count(*) FROM role_permissions rp WHERE rp.permission = permissions.name)
		FROM permissions WHERE name = $1 FOR UPDATE`, name).
		Scan(&label, &system, &grants)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if system {
		return ErrPermissionSystem
	}
	if grants > 0 {
		return ErrPermissionInUse
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM permissions WHERE name = $1`, name); err != nil {
		return err
	}
	return tx.Commit()
}

// mayAdministerCatalog reports whether the actor may change the shared catalog.
// The catalog is installation-wide, so this is a system administrator or an owner
// of some tenant, which is the permission that already means "administer the
// installation".
func (s *Store) mayAdministerCatalog(ctx context.Context, actorID string) (bool, error) {
	return mayAdministerCatalog(ctx, s.db, actorID)
}

func mayAdministerCatalog(ctx context.Context, q querier, actorID string) (bool, error) {
	var permitted bool
	err := q.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM system_administrators WHERE user_id = $1)
		    OR `+permissionPredicate("scoped.tenant_id", "$1", "$2"),
		actorID, string(role.ManageTenants)).Scan(&permitted)
	return permitted, err
}

// grantablePermissions returns what an actor may hand to somebody: the
// permissions they hold, plus -- for whoever administers the shared catalog --
// every custom permission.
//
// The second half is what makes the catalog usable. A permission nobody holds
// yet could not otherwise be granted, because the escalation guard refuses to
// hand out a capability the granter does not have. Letting the author of a
// permission pass it on resolves that without weakening the guard for enforced
// permissions, which are never in the custom set.
func grantablePermissions(ctx context.Context, q querier, actorID, tenantID string) ([]string, error) {
	held, err := heldPermissions(ctx, q, actorID, tenantID)
	if err != nil {
		return nil, err
	}
	administers, err := mayAdministerCatalog(ctx, q, actorID)
	if err != nil || !administers {
		return held, err
	}
	rows, err := q.QueryContext(ctx, `SELECT name FROM permissions WHERE NOT is_system`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if !slices.Contains(held, name) {
			held = append(held, name)
		}
	}
	return held, rows.Err()
}

// permissionOrder lists the enforced capabilities so the catalog keeps the same
// most-sensitive-first order the role editor used before it was a table.
var permissionOrder = `ARRAY[
	'tenants.manage', 'roles.manage', 'users.manage', 'applications.manage',
	'keys.manage', 'contracts.manage', 'users.read', 'console.read', 'profile.edit'
]`
