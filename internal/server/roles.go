package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/danyel/go-loose/internal/store"
)

const (
	maxRoleName        = 100
	maxRoleDescription = 500
)

// rolesPage serves the role management screen.
func (s *Server) rolesPage(w http.ResponseWriter, _ *http.Request) {
	s.serveEmbedded(w, "roles.html")
}

// listRoles serves the role management screen's data: every built-in role plus
// the tenant's own, each annotated with whether the caller may assign it.
func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := s.requestTenant(w, r)
	if !ok {
		return
	}
	roles, err := s.store.ListRoles(r.Context(), claimsFrom(r).UserID, tenantID)
	if err != nil {
		s.handleStoreError(w, "list roles", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

// createRole adds a role to the tenant. The store refuses a role that grants
// more than the caller holds, so the endpoint does not have to restate that rule.
func (s *Server) createRole(w http.ResponseWriter, r *http.Request) {
	var request struct {
		TenantID    string   `json:"tenant_id"`
		Slug        string   `json:"slug"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	slug := strings.TrimSpace(request.Slug)
	name := strings.TrimSpace(request.Name)
	description := strings.TrimSpace(request.Description)
	if !validSlug(slug) {
		writeError(w, http.StatusBadRequest, "slug must be lowercase letters, digits, and dashes")
		return
	}
	if name == "" || len(name) > maxRoleName {
		writeError(w, http.StatusBadRequest, "name must be between 1 and 100 characters")
		return
	}
	if len(description) > maxRoleDescription {
		writeError(w, http.StatusBadRequest, "description must be 500 characters or fewer")
		return
	}
	created, err := s.store.CreateRole(
		r.Context(), claimsFrom(r).UserID, request.TenantID, slug, name, description, request.Permissions)
	if err != nil {
		if errors.Is(err, store.ErrRoleSlugTaken) {
			writeError(w, http.StatusConflict, "a role with this slug already exists in this tenant")
			return
		}
		if errors.Is(err, store.ErrUnknownPermission) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.handleStoreError(w, "create role", err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// updateRole renames a role and replaces the permissions it grants.
func (s *Server) updateRole(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	name := strings.TrimSpace(request.Name)
	description := strings.TrimSpace(request.Description)
	if name == "" || len(name) > maxRoleName {
		writeError(w, http.StatusBadRequest, "name must be between 1 and 100 characters")
		return
	}
	if len(description) > maxRoleDescription {
		writeError(w, http.StatusBadRequest, "description must be 500 characters or fewer")
		return
	}
	updated, err := s.store.UpdateRole(
		r.Context(), claimsFrom(r).UserID, r.PathValue("id"), name, description, request.Permissions)
	if err != nil {
		if errors.Is(err, store.ErrUnknownPermission) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.handleStoreError(w, "update role", err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// deleteRole removes one of the tenant's own roles.
func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteRole(r.Context(), claimsFrom(r).UserID, r.PathValue("id")); err != nil {
		if errors.Is(err, store.ErrRoleInUse) {
			writeError(w, http.StatusConflict, "reassign the members of this role before deleting it")
			return
		}
		s.handleStoreError(w, "delete role", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// requestTenant reads the tenant a request targets, preferring an explicit
// tenant_id and falling back to the tenant named by the host so that the role
// screen works on a tenant subdomain.
func (s *Server) requestTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	if tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id")); tenantID != "" {
		return tenantID, true
	}
	slug := s.requestTenantSlug(r.Host)
	if slug == "" {
		writeError(w, http.StatusBadRequest, "tenant_id is required")
		return "", false
	}
	tenants, err := s.store.ListTenants(r.Context(), claimsFrom(r).UserID)
	if err != nil {
		s.handleStoreError(w, "resolve tenant", err)
		return "", false
	}
	for _, tenant := range tenants {
		if tenant.Slug == slug {
			return tenant.ID, true
		}
	}
	writeError(w, http.StatusNotFound, "resource not found or permission denied")
	return "", false
}
