package behaviour

import (
	"net/http"
	"testing"
)

// membershipPhases creates the person the hosted-login flow signs in as, and gives
// them exactly the two things a tenant application needs: membership of the tenant
// and access to its application.
func membershipPhases(t *testing.T, j *journey) {
	t.Helper()
	host := j.adminHost()
	j.memberEmail = "member@behaviour.test"
	j.memberPassword = "member-password-2026"

	phase(t, "a role is chosen from the tenant's catalogue", func(t *testing.T) {
		type role struct {
			ID          string   `json:"id"`
			Slug        string   `json:"slug"`
			System      bool     `json:"system"`
			Permissions []string `json:"permissions"`
			Assignable  bool     `json:"assignable"`
		}
		type listing struct {
			Roles []role `json:"roles"`
		}
		response := j.admin.get(host, "/api/v1/roles?tenant_id="+j.scopedTenantID, nil)
		roles := decode[listing](t, response, http.StatusOK)
		if len(roles.Roles) < 6 {
			t.Fatalf("roles = %d, want at least the six built-ins", len(roles.Roles))
		}
		seen := map[string]bool{}
		for _, item := range roles.Roles {
			seen[item.Slug] = true
			if item.Slug == "user" {
				j.userRoleID = item.ID
			}
			if item.Slug == "viewer" {
				j.viewerRoleID = item.ID
			}
		}
		for _, want := range []string{"owner", "admin", "developer", "operator", "viewer", "user"} {
			if !seen[want] {
				t.Errorf("built-in role %q is missing", want)
			}
		}
		if j.userRoleID == "" || j.viewerRoleID == "" {
			t.Fatal("could not resolve the built-in roles")
		}
	})

	phase(t, "an email address that is not a plain address is refused", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, host, "/api/v1/users", map[string]any{
			"tenant_id": j.scopedTenantID, "email": "Real Name <member@behaviour.test>",
			"role_id": j.viewerRoleID, "password": j.memberPassword,
		})
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "a short password is refused", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, host, "/api/v1/users", map[string]any{
			"tenant_id": j.scopedTenantID, "email": "weak@behaviour.test",
			"role_id": j.viewerRoleID, "password": "short",
		})
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "a member is invited and given access to the application", func(t *testing.T) {
		type invited struct {
			ID          string   `json:"id"`
			Email       string   `json:"email"`
			DisplayName string   `json:"display_name"`
			Role        string   `json:"role"`
			RoleID      string   `json:"role_id"`
			Status      string   `json:"status"`
			Permissions []string `json:"permissions"`
		}
		response := j.admin.json(http.MethodPost, host, "/api/v1/users", map[string]any{
			"tenant_id": j.scopedTenantID, "email": j.memberEmail,
			"display_name": "Behaviour Member", "role_id": j.viewerRoleID,
			"password": j.memberPassword,
		})
		member := decode[invited](t, response, http.StatusCreated)
		if member.Email != j.memberEmail {
			t.Errorf("email = %q", member.Email)
		}
		if member.Status != "invited" {
			// An invitation is not a login: the account stays "invited" until the
			// person signs in for the first time.
			t.Errorf("status = %q, want invited", member.Status)
		}
		if member.Role != "viewer" {
			t.Errorf("role = %q, want viewer", member.Role)
		}
		j.memberID = member.ID

		// Membership alone is not enough: the client login flow also needs an
		// application grant.
		access := j.admin.json(http.MethodPut, host, "/api/v1/users/"+member.ID+"/access", map[string]any{
			"tenant_id": j.scopedTenantID, "role_id": j.viewerRoleID,
			"application_ids": []string{j.applicationID},
		})
		if access.StatusCode != http.StatusNoContent {
			t.Fatalf("grant access = %d: %s", access.StatusCode, bodyOf(t, access))
		}

		var granted int
		if err := j.h.db.QueryRowContext(t.Context(), `
			SELECT count(*) FROM user_application_access
			WHERE user_id = $1 AND application_id = $2`, member.ID, j.applicationID).Scan(&granted); err != nil {
			t.Fatalf("count grants: %v", err)
		}
		if granted != 1 {
			t.Errorf("application grants = %d, want 1", granted)
		}
	})

	phase(t, "a second member is invited without any application grant", func(t *testing.T) {
		// Membership and application access are separate decisions, and the client
		// login flow depends on the difference.
		j.ungrantedEmail = "ungranted@behaviour.test"
		j.ungrantedPassword = "ungranted-password-2026"
		response := j.admin.json(http.MethodPost, host, "/api/v1/users", map[string]any{
			"tenant_id": j.scopedTenantID, "email": j.ungrantedEmail,
			"display_name": "Ungranted Member", "role_id": j.userRoleID,
			"password": j.ungrantedPassword,
		})
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("invite = %d: %s", response.StatusCode, bodyOf(t, response))
		}
		var grants int
		if err := j.h.db.QueryRowContext(t.Context(), `
			SELECT count(*) FROM user_application_access WHERE user_id = (
				SELECT id FROM users WHERE email = $1)`, j.ungrantedEmail).Scan(&grants); err != nil {
			t.Fatalf("count grants: %v", err)
		}
		if grants != 0 {
			t.Errorf("grants = %d, want none", grants)
		}
		if err := j.h.db.QueryRowContext(t.Context(),
			`SELECT id FROM users WHERE email = $1`, j.ungrantedEmail).Scan(&j.ungrantedMemberID); err != nil {
			t.Fatalf("look up the ungranted member: %v", err)
		}
	})

	phase(t, "the member appears in the tenant's user list", func(t *testing.T) {
		type listing struct {
			Users []struct {
				ID             string   `json:"id"`
				Email          string   `json:"email"`
				Role           string   `json:"role"`
				Permissions    []string `json:"permissions"`
				ApplicationIDs []string `json:"application_ids"`
			} `json:"users"`
		}
		result := decode[listing](t, j.admin.get(host, "/api/v1/dashboard", nil), http.StatusOK)
		found := false
		for _, user := range result.Users {
			if user.Email == j.memberEmail {
				found = true
				if len(user.ApplicationIDs) != 1 {
					t.Errorf("application grants reported = %v", user.ApplicationIDs)
				}
			}
		}
		if !found {
			t.Errorf("%s is missing from the dashboard", j.memberEmail)
		}
	})
}
