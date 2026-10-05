package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/danyel/go-loose/internal/role"
)

// Role is a named bundle of permissions. A role with no TenantID is built in:
// every tenant sees it and it cannot be edited or deleted. A role with a
// TenantID belongs to that tenant alone.
type Role struct {
	ID          string  `json:"id"`
	TenantID    *string `json:"tenant_id,omitempty"`
	Slug        string  `json:"slug"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	System      bool    `json:"system"`
	// Permissions is sorted so that the console can compare two roles without
	// worrying about the order they were stored in.
	Permissions []string `json:"permissions"`
	MemberCount int      `json:"member_count"`
	// Assignable reports whether the requesting administrator may hand this role
	// to somebody. A role is assignable only when every permission it grants is
	// one the administrator already holds, so managing members can never be used
	// to grant more authority than the administrator has.
	Assignable bool `json:"assignable"`
}

var (
	// ErrRoleInUse is returned when a role that still has members is deleted.
	ErrRoleInUse = errors.New("role is still assigned to members")
	// ErrRoleSlugTaken is returned when a tenant already uses the requested slug.
	ErrRoleSlugTaken = errors.New("role slug is already in use")
	// ErrUnknownPermission is returned when a role or catalog entry names a
	// permission that is not in the catalog. It is a caller mistake rather than a
	// server fault, so callers report it as a bad request.
	ErrUnknownPermission = errors.New("unknown permission")
)

// querier is satisfied by both *sql.DB and *sql.Tx so that the authorization
// helpers can run inside or outside a transaction.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

// permissionPredicate renders the one authorization check used by every
// tenant-scoped statement: it holds when the user holds permission in the
// tenant. The arguments are SQL expressions rather than placeholders because the
// queries that need it have already joined memberships under a name of their
// own. Resolving the grant through role_permissions is what lets a tenant define
// its own roles without any Go code having to know they exist.
func permissionPredicate(tenantExpr, userExpr, permissionExpr string) string {
	return fmt.Sprintf(`EXISTS (
			SELECT 1
			FROM memberships scoped
			JOIN role_permissions granted ON granted.role_id = scoped.role_id
			WHERE scoped.tenant_id = %s AND scoped.user_id = %s
			  AND granted.permission = %s
		)`, tenantExpr, userExpr, permissionExpr)
}

// SystemRoleID returns the id of a built-in role. Callers that seed memberships
// outside a tenant context -- the installer, the bootstrapper -- need it because
// a membership is a role id rather than a name.
func (s *Store) SystemRoleID(ctx context.Context, slug string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM roles WHERE slug = $1 AND tenant_id IS NULL`, slug).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

// clientPermissions is the permission aggregate reported to client applications
// through /connect/userinfo. A user with no membership in the owning tenant is
// described by the built-in User role, which is the least privileged one.
const clientPermissions = `COALESCE(
		(SELECT json_agg(rp.permission ORDER BY rp.permission)
		 FROM role_permissions rp WHERE rp.role_id = m.role_id),
		(SELECT json_agg(rp.permission ORDER BY rp.permission)
		 FROM role_permissions rp
		 JOIN roles fallback ON fallback.id = rp.role_id
		 WHERE fallback.slug = 'user' AND fallback.tenant_id IS NULL),
		'[]'::json)`

// heldPermissions returns every permission the actor holds in a tenant, sorted.
// It is the basis for both the per-action checks and the escalation guard: an
// actor may never hand out a capability they do not have themselves.
func heldPermissions(ctx context.Context, q querier, actorID, tenantID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT DISTINCT granted.permission
		FROM memberships scoped
		JOIN role_permissions granted ON granted.role_id = scoped.role_id
		WHERE scoped.tenant_id = $1 AND scoped.user_id = $2
		ORDER BY granted.permission`, tenantID, actorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	held := make([]string, 0)
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, err
		}
		held = append(held, permission)
	}
	return held, rows.Err()
}

// hasPermission reports whether the actor holds one permission in a tenant.
func hasPermission(ctx context.Context, q querier, actorID, tenantID string, permission role.Permission) (bool, error) {
	var permitted bool
	err := q.QueryRowContext(ctx,
		`SELECT `+permissionPredicate("$2", "$1", "$3"),
		actorID, tenantID, string(permission)).Scan(&permitted)
	return permitted, err
}

// within reports whether every permission in granted also appears in held.
func within(granted, held []string) bool {
	available := make(map[string]bool, len(held))
	for _, permission := range held {
		available[permission] = true
	}
	for _, permission := range granted {
		if !available[permission] {
			return false
		}
	}
	return true
}

// normalizePermissions checks that every submitted name is in the catalog and
// returns them deduplicated in a stable order. Validation moved from the Go
// vocabulary to the database when permissions became rows, so a tenant-defined
// permission can be granted like any other while an invented one still cannot be
// stored.
func normalizePermissions(ctx context.Context, q querier, permissions []string) ([]string, error) {
	requested := make(map[string]bool, len(permissions))
	for _, value := range permissions {
		name := strings.TrimSpace(value)
		if name == "" {
			continue
		}
		var known bool
		if err := q.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM permissions WHERE name = $1)`, name).Scan(&known); err != nil {
			return nil, err
		}
		if !known {
			return nil, fmt.Errorf("%w: %q", ErrUnknownPermission, name)
		}
		requested[name] = true
	}
	rows, err := q.QueryContext(ctx, `
		SELECT name FROM permissions
		WHERE name = ANY($1)
		ORDER BY array_position(`+permissionOrder+`, name) NULLS LAST, name`, keys(requested))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]string, 0, len(requested))
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		result = append(result, name)
	}
	return result, rows.Err()
}

// keys returns the members of a set as a slice, for use as a SQL array parameter.
func keys(set map[string]bool) []string {
	result := make([]string, 0, len(set))
	for name := range set {
		result = append(result, name)
	}
	return result
}

// roleGrants reads a role's permissions.
func roleGrants(ctx context.Context, q querier, roleID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT permission FROM role_permissions WHERE role_id = $1 ORDER BY permission`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]string, 0)
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, err
		}
		result = append(result, permission)
	}
	return result, rows.Err()
}

func scanRole(row scanner) (Role, error) {
	var item Role
	var tenantID sql.NullString
	if err := row.Scan(&item.ID, &tenantID, &item.Slug, &item.Name, &item.Description,
		&item.System, &item.MemberCount); err != nil {
		return Role{}, err
	}
	if tenantID.Valid {
		item.TenantID = &tenantID.String
	}
	return item, nil
}

const roleSelect = `
	SELECT r.id, r.tenant_id, r.slug, r.name, r.description, r.is_system,
	       (SELECT count(*) FROM memberships m WHERE m.role_id = r.id)
	FROM roles r `

// ListRoles returns the roles available in a tenant: every built-in role plus
// that tenant's own. Reading the catalog needs users.read so the role screen can
// describe a role before anybody is assigned it.
func (s *Store) ListRoles(ctx context.Context, actorID, tenantID string) ([]Role, error) {
	permitted, err := hasPermission(ctx, s.db, actorID, tenantID, role.ReadUsers)
	if err != nil {
		return nil, err
	}
	if !permitted {
		return nil, ErrNotFound
	}
	roles, err := s.rolesIn(ctx, s.db, actorID, tenantID)
	if err != nil {
		return nil, err
	}
	return roles, nil
}

// AssignableRoles returns only the roles the administrator may hand to a member.
func (s *Store) AssignableRoles(ctx context.Context, actorID, tenantID string) ([]Role, error) {
	roles, err := s.ListRoles(ctx, actorID, tenantID)
	if err != nil {
		return nil, err
	}
	result := make([]Role, 0, len(roles))
	for _, item := range roles {
		if item.Assignable {
			result = append(result, item)
		}
	}
	return result, nil
}

// rolesIn loads the tenant's catalog and marks what the actor may assign.
func (s *Store) rolesIn(ctx context.Context, q querier, actorID, tenantID string) ([]Role, error) {
	rows, err := q.QueryContext(ctx, roleSelect+`
		WHERE r.tenant_id IS NULL OR r.tenant_id = $1
		ORDER BY r.is_system DESC,
		         array_position(ARRAY['owner','admin','developer','operator','viewer','user'], r.slug) NULLS LAST,
		         r.name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	held, err := heldPermissions(ctx, q, actorID, tenantID)
	if err != nil {
		return nil, err
	}
	result := make([]Role, 0)
	for rows.Next() {
		item, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		permissions, err := roleGrants(ctx, q, item.ID)
		if err != nil {
			return nil, err
		}
		item.Permissions = permissions
		item.Assignable = within(permissions, held)
		result = append(result, item)
	}
	return result, rows.Err()
}

func roleByID(ctx context.Context, q querier, roleID string) (Role, error) {
	item, err := scanRole(q.QueryRowContext(ctx, roleSelect+`WHERE r.id = $1`, roleID))
	if errors.Is(err, sql.ErrNoRows) {
		return Role{}, ErrNotFound
	}
	if err != nil {
		return Role{}, err
	}
	return item, nil
}

// CreateRole adds a tenant's own role. The caller must hold roles.manage and may
// not mint a role more powerful than one they already hold.
func (s *Store) CreateRole(ctx context.Context, actorID, tenantID, slug, name, description string, permissions []string) (Role, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Role{}, err
	}
	defer tx.Rollback()
	granted, err := normalizePermissions(ctx, tx, permissions)
	if err != nil {
		return Role{}, err
	}

	permitted, err := hasPermission(ctx, tx, actorID, tenantID, role.ManageRoles)
	if err != nil {
		return Role{}, err
	}
	if !permitted {
		return Role{}, ErrNotFound
	}
	grantable, err := grantablePermissions(ctx, tx, actorID, tenantID)
	if err != nil {
		return Role{}, err
	}
	if !within(granted, grantable) {
		return Role{}, ErrNotFound
	}
	created, err := insertRole(ctx, tx, tenantID, slug, name, description)
	if err != nil {
		return Role{}, err
	}
	for _, permission := range granted {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO role_permissions(role_id, permission) VALUES ($1, $2)`,
			created.ID, permission); err != nil {
			return Role{}, err
		}
	}
	created.Permissions = granted
	created.Assignable = true
	return created, tx.Commit()
}

// UpdateRole renames a role and replaces its permissions. Built-in roles are
// immutable and a tenant may only edit a role it owns.
func (s *Store) UpdateRole(ctx context.Context, actorID, roleID, name, description string, permissions []string) (Role, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Role{}, err
	}
	defer tx.Rollback()
	granted, err := normalizePermissions(ctx, tx, permissions)
	if err != nil {
		return Role{}, err
	}

	existing, err := lockRole(ctx, tx, roleID)
	if err != nil {
		return Role{}, err
	}
	if existing.System || existing.TenantID == nil {
		return Role{}, ErrNotFound
	}
	permitted, err := hasPermission(ctx, tx, actorID, *existing.TenantID, role.ManageRoles)
	if err != nil {
		return Role{}, err
	}
	if !permitted {
		return Role{}, ErrNotFound
	}
	grantable, err := grantablePermissions(ctx, tx, actorID, *existing.TenantID)
	if err != nil {
		return Role{}, err
	}
	if !within(granted, grantable) {
		return Role{}, ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE roles SET name = $2, description = $3, updated_at = now() WHERE id = $1`,
		roleID, name, description); err != nil {
		return Role{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, roleID); err != nil {
		return Role{}, err
	}
	for _, permission := range granted {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO role_permissions(role_id, permission) VALUES ($1, $2)`,
			roleID, permission); err != nil {
			return Role{}, err
		}
	}
	existing.Name, existing.Description, existing.Permissions = name, description, granted
	return existing, tx.Commit()
}

// DeleteRole removes a tenant's own role. Built-in roles and roles that still
// have members cannot be deleted, so nobody is left pointing at nothing.
func (s *Store) DeleteRole(ctx context.Context, actorID, roleID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existing, err := lockRole(ctx, tx, roleID)
	if err != nil {
		return err
	}
	if existing.System || existing.TenantID == nil {
		return ErrNotFound
	}
	permissions, err := roleGrants(ctx, tx, roleID)
	if err != nil {
		return err
	}
	permitted, err := hasPermission(ctx, tx, actorID, *existing.TenantID, role.ManageRoles)
	if err != nil {
		return err
	}
	if !permitted {
		return ErrNotFound
	}
	grantable, err := grantablePermissions(ctx, tx, actorID, *existing.TenantID)
	if err != nil {
		return err
	}
	if !within(permissions, grantable) {
		return ErrNotFound
	}
	if existing.MemberCount > 0 {
		return ErrRoleInUse
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM roles WHERE id = $1`, roleID); err != nil {
		return err
	}
	return tx.Commit()
}

// resolveRoleID validates that a role may be assigned to a member of the tenant
// and returns its id. A role belonging to another tenant is reported as not
// found so that role ids cannot be probed across tenants.
func resolveRoleID(ctx context.Context, tx *sql.Tx, tenantID, roleID string, held []string) (string, error) {
	item, err := roleByID(ctx, tx, roleID)
	if err != nil {
		return "", err
	}
	if item.TenantID != nil && *item.TenantID != tenantID {
		return "", ErrNotFound
	}
	granted, err := roleGrants(ctx, tx, roleID)
	if err != nil {
		return "", err
	}
	if !within(granted, held) {
		return "", ErrNotFound
	}
	return roleID, nil
}

// lockRole loads a role and holds the row for the rest of the transaction.
func lockRole(ctx context.Context, tx *sql.Tx, roleID string) (Role, error) {
	item, err := scanRole(tx.QueryRowContext(ctx, roleSelect+`WHERE r.id = $1 FOR UPDATE`, roleID))
	if errors.Is(err, sql.ErrNoRows) {
		return Role{}, ErrNotFound
	}
	if err != nil {
		return Role{}, err
	}
	permissions, err := roleGrants(ctx, tx, roleID)
	if err != nil {
		return Role{}, err
	}
	item.Permissions = permissions
	return item, nil
}

// insertRole writes the role row, translating a slug collision into a stable
// error rather than a driver-specific constraint violation.
func insertRole(ctx context.Context, tx *sql.Tx, tenantID, slug, name, description string) (Role, error) {
	item, err := scanRole(tx.QueryRowContext(ctx, `
		INSERT INTO roles(tenant_id, slug, name, description)
		VALUES ($1, $2, $3, $4)
		RETURNING id, tenant_id, slug, name, description, is_system, 0`,
		tenantID, slug, name, description))
	if err != nil {
		if isUniqueViolation(err) {
			return Role{}, ErrRoleSlugTaken
		}
		return Role{}, err
	}
	return item, nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate key value")
}
