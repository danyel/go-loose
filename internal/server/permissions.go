package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/danyel/go-loose/internal/store"
)

const maxPermissionLabel = 100

// listPermissions serves the whole catalog. Every management session may read it,
// because the role editor needs it to render its checkboxes.
func (s *Server) listPermissions(w http.ResponseWriter, r *http.Request) {
	catalog, err := s.store.ListPermissions(r.Context())
	if err != nil {
		s.internalError(w, "list permissions", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": catalog})
}

// createPermission adds a name to the shared catalog so that roles can grant it.
//
// The catalog is installation-wide, so this is restricted to a system
// administrator or a holder of tenants.manage. Note what the new name does and
// does not do: it becomes grantable and is reported through /connect/userinfo,
// but nothing in the console checks for it, so it cannot unlock console
// behaviour. The response says so, and the UI repeats it.
func (s *Server) createPermission(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name        string `json:"name"`
		Label       string `json:"label"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	name := strings.TrimSpace(request.Name)
	if !store.ValidPermissionName(name) {
		writeError(w, http.StatusBadRequest,
			"name must be lowercase words separated by dots, for example reports.export")
		return
	}
	label := strings.TrimSpace(request.Label)
	if label == "" || len(label) > maxPermissionLabel {
		writeError(w, http.StatusBadRequest, "label must be between 1 and 100 characters")
		return
	}
	description := strings.TrimSpace(request.Description)
	if len(description) > 500 {
		writeError(w, http.StatusBadRequest, "description must be 500 characters or fewer")
		return
	}
	created, err := s.store.CreatePermission(
		r.Context(), claimsFrom(r).UserID, name, label, description)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrPermissionTaken):
			writeError(w, http.StatusConflict, "this permission already exists")
		case errors.Is(err, store.ErrUnknownPermission):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			s.handleStoreError(w, "create permission", err)
		}
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// deletePermission removes a catalog entry that no role grants.
func (s *Server) deletePermission(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !store.ValidPermissionName(name) {
		writeError(w, http.StatusBadRequest, "unknown permission name")
		return
	}
	if err := s.store.DeletePermission(r.Context(), claimsFrom(r).UserID, name); err != nil {
		switch {
		case errors.Is(err, store.ErrPermissionInUse):
			writeError(w, http.StatusConflict, "remove this permission from every role before deleting it")
		case errors.Is(err, store.ErrPermissionSystem):
			writeError(w, http.StatusConflict, "built-in permissions cannot be deleted")
		default:
			s.handleStoreError(w, "delete permission", err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
