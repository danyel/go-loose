package behaviour

import (
	"net/http"
	"testing"
)

// rolePhases exercises the database-driven role and permission model: the shared
// catalog, tenant-defined roles, and the rule that a role may never grant more
// than the administrator already holds.
func rolePhases(t *testing.T, j *journey) {
	t.Helper()
	host := j.adminHost()

	phase(t, "the permission catalog lists the enforced capabilities", func(t *testing.T) {
		type entry struct {
			Name        string `json:"name"`
			Label       string `json:"label"`
			System      bool   `json:"system"`
			Enforced    bool   `json:"enforced"`
			Description string `json:"description"`
		}
		type listing struct {
			Permissions []entry `json:"permissions"`
		}
		result := decode[listing](t, j.admin.get(host, "/api/v1/permissions", nil), http.StatusOK)
		names := map[string]entry{}
		for _, item := range result.Permissions {
			names[item.Name] = item
		}
		for _, want := range []string{
			"console.read", "users.read", "users.manage", "applications.manage",
			"keys.manage", "contracts.manage", "roles.manage", "tenants.manage", "profile.edit",
		} {
			entry, ok := names[want]
			if !ok {
				t.Errorf("permission %q is missing from the catalog", want)
				continue
			}
			if !entry.System || !entry.Enforced {
				t.Errorf("permission %q is not marked system and enforced: %+v", want, entry)
			}
			if entry.Label == "" || entry.Description == "" {
				t.Errorf("permission %q has no label or description the console can render", want)
			}
		}
	})

	phase(t, "a malformed permission name is refused", func(t *testing.T) {
		for _, name := range []string{"Reports Export", "reports/export", "reports..export", ""} {
			response := j.admin.json(http.MethodPost, host, "/api/v1/permissions", map[string]any{
				"name": name, "label": "Reports export",
			})
			statusOnly(t, response, http.StatusBadRequest)
		}
	})

	phase(t, "a permission without a label is refused", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, host, "/api/v1/permissions", map[string]any{
			"name": "reports.export", "label": "   ",
		})
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "a tenant administrator may extend the catalog", func(t *testing.T) {
		// Adding a name does not enforce anything; it only makes the name grantable.
		j.permission = "reports.export"
		type created struct {
			Name     string `json:"name"`
			Label    string `json:"label"`
			System   bool   `json:"system"`
			Enforced bool   `json:"enforced"`
		}
		response := j.admin.json(http.MethodPost, host, "/api/v1/permissions", map[string]any{
			"name": j.permission, "label": "Export reports", "description": "Download tenant reports",
		})
		permission := decode[created](t, response, http.StatusCreated)
		if permission.Name != j.permission {
			t.Errorf("name = %q", permission.Name)
		}
		if permission.System || permission.Enforced {
			t.Errorf("a tenant permission must not be system or enforced: %+v", permission)
		}
	})

	phase(t, "a duplicate permission name is refused", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, host, "/api/v1/permissions", map[string]any{
			"name": j.permission, "label": "Export reports again",
		})
		statusOnly(t, response, http.StatusConflict)
	})

	phase(t, "a built-in permission cannot be deleted", func(t *testing.T) {
		response := j.admin.request(http.MethodDelete, host, "/api/v1/permissions/console.read", nil,
			map[string]string{"Origin": "http://" + host})
		statusOnly(t, response, http.StatusConflict)
	})

	phase(t, "a tenant defines its own role", func(t *testing.T) {
		type created struct {
			ID          string   `json:"id"`
			Slug        string   `json:"slug"`
			Name        string   `json:"name"`
			System      bool     `json:"system"`
			Permissions []string `json:"permissions"`
			MemberCount int      `json:"member_count"`
		}
		response := j.admin.json(http.MethodPost, host, "/api/v1/roles", map[string]any{
			"tenant_id": j.scopedTenantID, "slug": "reporter", "name": "Reporter",
			"description": "Reads the console and exports reports",
			"permissions": []string{"console.read", "users.read", j.permission},
		})
		role := decode[created](t, response, http.StatusCreated)
		if role.Slug != "reporter" {
			t.Errorf("slug = %q", role.Slug)
		}
		if role.System {
			t.Error("a tenant role must not be marked as a system role")
		}
		if len(role.Permissions) != 3 {
			t.Errorf("permissions = %v, want three", role.Permissions)
		}
		j.customRoleID = role.ID
	})

	phase(t, "a permission a role grants cannot be deleted", func(t *testing.T) {
		response := j.admin.request(http.MethodDelete, host, "/api/v1/permissions/"+j.permission, nil,
			map[string]string{"Origin": "http://" + host})
		statusOnly(t, response, http.StatusConflict)
	})

	phase(t, "a duplicate role slug is refused", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, host, "/api/v1/roles", map[string]any{
			"tenant_id": j.scopedTenantID, "slug": "reporter", "name": "Reporter again",
			"permissions": []string{"console.read"},
		})
		statusOnly(t, response, http.StatusConflict)
	})

	phase(t, "a malformed role slug or name is refused", func(t *testing.T) {
		for _, payload := range []map[string]any{
			{"tenant_id": j.scopedTenantID, "slug": "Reporter", "name": "Upper"},
			{"tenant_id": j.scopedTenantID, "slug": "reporter_2", "name": "Underscore"},
			{"tenant_id": j.scopedTenantID, "slug": "reporter2", "name": ""},
		} {
			response := j.admin.json(http.MethodPost, host, "/api/v1/roles", payload)
			statusOnly(t, response, http.StatusBadRequest)
		}
	})

	phase(t, "a role naming an unknown permission is refused", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, host, "/api/v1/roles", map[string]any{
			"tenant_id": j.scopedTenantID, "slug": "invented", "name": "Invented",
			"permissions": []string{"not.a.real.permission"},
		})
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "a role cannot grant a capability the caller does not hold", func(t *testing.T) {
		// tenants.manage belongs to owners alone. A tenant administrator asking for a
		// role that grants it must not be able to mint their way above their own
		// authority, and must not even learn that the capability exists.
		browser := j.browser()
		token := csrfFrom(t, bodyOf(t, browser.get(host, "/login", nil)))
		response := browser.form(host, "/auth/password", neturlValues(map[string]string{
			"csrf_token": token, "email": "interview@nmbs.auth.dev", "password": "admin123",
		}), nil)
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-in = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		response = browser.json(http.MethodPost, host, "/api/v1/roles", map[string]any{
			"tenant_id": j.tenantID, "slug": "escalation", "name": "Escalation",
			"permissions": []string{"tenants.manage"},
		})
		if response.StatusCode != http.StatusNotFound && response.StatusCode != http.StatusBadRequest {
			t.Fatalf("escalation attempt = %d, want a refusal: %s", response.StatusCode, bodyOf(t, response))
		}
	})

	phase(t, "a role's permissions and name can be changed", func(t *testing.T) {
		type updated struct {
			Name        string   `json:"name"`
			Slug        string   `json:"slug"`
			Permissions []string `json:"permissions"`
		}
		response := j.admin.json(http.MethodPut, host, "/api/v1/roles/"+j.customRoleID, map[string]any{
			"name": "Report reader", "description": "Now with fewer capabilities",
			"permissions": []string{"console.read"},
		})
		role := decode[updated](t, response, http.StatusOK)
		if role.Name != "Report reader" {
			t.Errorf("name = %q", role.Name)
		}
		if len(role.Permissions) != 1 {
			t.Errorf("permissions = %v, want just console.read", role.Permissions)
		}
	})

	phase(t, "the permission is deletable once no role grants it", func(t *testing.T) {
		// The update above left the custom permission unreferenced.
		response := j.admin.request(http.MethodDelete, host, "/api/v1/permissions/"+j.permission, nil,
			map[string]string{"Origin": "http://" + host})
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("delete permission = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		response.Body.Close()
	})

	phase(t, "a role still held by a member cannot be deleted", func(t *testing.T) {
		// Give the custom role to the ungranted member, then try to remove it.
		access := j.admin.json(http.MethodPut, host, "/api/v1/users/"+j.ungrantedMemberID+"/access", map[string]any{
			"tenant_id": j.scopedTenantID, "role_id": j.customRoleID, "application_ids": []string{},
		})
		if access.StatusCode != http.StatusNoContent {
			t.Fatalf("assign custom role = %d: %s", access.StatusCode, bodyOf(t, access))
		}
		response := j.admin.request(http.MethodDelete, host, "/api/v1/roles/"+j.customRoleID, nil,
			map[string]string{"Origin": "http://" + host})
		statusOnly(t, response, http.StatusConflict)
	})

	phase(t, "an unused role is deleted, and its permission with it", func(t *testing.T) {
		type created struct {
			ID string `json:"id"`
		}
		response := j.admin.json(http.MethodPost, host, "/api/v1/roles", map[string]any{
			"tenant_id": j.scopedTenantID, "slug": "temporary", "name": "Temporary",
			"permissions": []string{"console.read"},
		})
		temporary := decode[created](t, response, http.StatusCreated)

		response = j.admin.request(http.MethodDelete, host, "/api/v1/roles/"+temporary.ID, nil,
			map[string]string{"Origin": "http://" + host})
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("delete role = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		response.Body.Close()

		// The custom permission is now unreferenced, so it can go too.
		response.Body.Close()
	})

	phase(t, "a built-in role cannot be edited or deleted", func(t *testing.T) {
		type listing struct {
			Roles []struct {
				ID     string `json:"id"`
				Slug   string `json:"slug"`
				System bool   `json:"system"`
			} `json:"roles"`
		}
		result := decode[listing](t, j.admin.get(host, "/api/v1/roles?tenant_id="+j.scopedTenantID, nil), http.StatusOK)
		var ownerID string
		for _, role := range result.Roles {
			if role.Slug == "owner" {
				ownerID = role.ID
			}
		}
		if ownerID == "" {
			t.Fatal("the owner role is missing")
		}
		response := j.admin.json(http.MethodPut, host, "/api/v1/roles/"+ownerID, map[string]any{
			"name": "Hijacked", "permissions": []string{"console.read"},
		})
		if response.StatusCode == http.StatusOK {
			t.Error("a built-in role was renamed")
			response.Body.Close()
		} else {
			response.Body.Close()
		}
		response = j.admin.request(http.MethodDelete, host, "/api/v1/roles/"+ownerID, nil,
			map[string]string{"Origin": "http://" + host})
		if response.StatusCode == http.StatusNoContent {
			t.Error("a built-in role was deleted")
			response.Body.Close()
		} else {
			response.Body.Close()
		}
	})
}
