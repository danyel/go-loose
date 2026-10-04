package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/danyel/go-loose/internal/role"
	"github.com/danyel/go-loose/internal/store"
)

// rolesFixture creates a tenant owned by owner plus a developer member. The
// developer is the interesting actor: it administers members but does not hold
// roles.manage, so it is the boundary the escalation guards are tested against.
func rolesFixture(t *testing.T) (s *store.Store, ctx context.Context, owner, developer, tenantID string) {
	t.Helper()
	s, _, ctx = integrationStore(t)
	owner = newUser(t, s, ctx, "owner@example.test")
	tenantID = newTenant(t, s, ctx, owner, "nmbs").ID
	developer = addMember(t, s, ctx, owner, tenantID, "developer@example.test", "developer")
	return s, ctx, owner, developer, tenantID
}

func systemRole(t *testing.T, s *store.Store, ctx context.Context, slug string) string {
	t.Helper()
	id, err := s.SystemRoleID(ctx, slug)
	if err != nil {
		t.Fatalf("look up built-in role %q: %v", slug, err)
	}
	return id
}

func TestTenantCanDefineItsOwnRoleAndItIsEnforced(t *testing.T) {
	s, ctx, owner, _, tenantID := rolesFixture(t)
	application, err := s.CreateApplication(ctx, owner, store.Application{
		TenantID: tenantID, Slug: "guess", Name: "Guess", AllowedHosts: []string{},
	})
	if err != nil {
		t.Fatalf("create application: %v", err)
	}

	created, err := s.CreateRole(ctx, owner, tenantID, "release-manager",
		"Release manager", "Prepares releases.",
		[]string{string(role.ReadConsole), string(role.ManageContracts), string(role.ReadUsers)})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if created.System {
		t.Error("a tenant role must not be marked as built in")
	}
	if created.TenantID == nil || *created.TenantID != tenantID {
		t.Errorf("tenant id = %v, want %s", created.TenantID, tenantID)
	}
	if !contains(created.Permissions, string(role.ManageContracts)) {
		t.Errorf("permissions = %v, want contracts.manage", created.Permissions)
	}

	// The role grants exactly what it says and nothing more.
	member := addMember(t, s, ctx, owner, tenantID, "member@example.test", "viewer")
	if err := s.SetUserAccess(ctx, owner, tenantID, member, created.ID, nil); err != nil {
		t.Fatalf("assign the custom role: %v", err)
	}
	_, err = s.CreateAPIKey(ctx, member, application.ID, "key", "gl_prefix", secretHash("custom-denied"), nil)
	assertPermission(t, "custom role issuing a key", err, false)
	_, err = s.SaveContract(ctx, member, application.ID, contractDocument(), nil)
	assertPermission(t, "custom role importing a contract", err, true)
}

func TestCustomRoleIsScopedToItsOwnTenant(t *testing.T) {
	s, ctx, owner, _, tenantID := rolesFixture(t)
	other := newUser(t, s, ctx, "other-owner@example.test")
	otherTenant := newTenant(t, s, ctx, other, "ypto").ID

	created, err := s.CreateRole(ctx, owner, tenantID, "auditor", "Auditor", "", []string{string(role.ReadConsole)})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	roles, err := s.ListRoles(ctx, other, otherTenant)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	for _, item := range roles {
		if item.ID == created.ID {
			t.Fatal("a role leaked across tenants")
		}
	}
	if err := s.DeleteRole(ctx, other, created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant delete = %v, want ErrNotFound", err)
	}
	if _, err := s.UpdateRole(ctx, other, created.ID, "Hijacked", "", nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant update = %v, want ErrNotFound", err)
	}
}

func TestBuiltInRolesCannotBeEditedOrDeleted(t *testing.T) {
	s, ctx, owner, _, _ := rolesFixture(t)
	ownerRole := systemRole(t, s, ctx, "owner")
	if _, err := s.UpdateRole(ctx, owner, ownerRole, "Supreme", "", nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("editing a built-in role = %v, want ErrNotFound", err)
	}
	if err := s.DeleteRole(ctx, owner, ownerRole); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleting a built-in role = %v, want ErrNotFound", err)
	}
}

func TestRoleInUseCannotBeDeleted(t *testing.T) {
	s, ctx, owner, _, tenantID := rolesFixture(t)
	created, err := s.CreateRole(ctx, owner, tenantID, "support", "Support", "", []string{string(role.ReadConsole)})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	member := addMember(t, s, ctx, owner, tenantID, "member@example.test", "viewer")
	if err := s.SetUserAccess(ctx, owner, tenantID, member, created.ID, nil); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if err := s.DeleteRole(ctx, owner, created.ID); !errors.Is(err, store.ErrRoleInUse) {
		t.Fatalf("delete an assigned role = %v, want ErrRoleInUse", err)
	}
	// Once nobody holds it the delete goes through.
	if err := s.SetUserAccess(ctx, owner, tenantID, member, systemRole(t, s, ctx, "viewer"), nil); err != nil {
		t.Fatalf("move the member off the role: %v", err)
	}
	if err := s.DeleteRole(ctx, owner, created.ID); err != nil {
		t.Fatalf("delete an unused role: %v", err)
	}
}

// TestRoleAssignmentCannotEscalate is the guard that matters most now that
// developer and operator may manage members: they must not be able to hand
// somebody a role more powerful than their own, which would otherwise be a
// straightforward route to owner.
func TestRoleAssignmentCannotEscalate(t *testing.T) {
	s, ctx, owner, developer, tenantID := rolesFixture(t)
	victim := addMember(t, s, ctx, owner, tenantID, "victim@example.test", "viewer")
	ownerRole := systemRole(t, s, ctx, "owner")

	if err := s.SetUserAccess(ctx, developer, tenantID, victim, ownerRole, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("developer promoting a member to owner = %v, want ErrNotFound", err)
	}
	if _, err := s.InviteUser(ctx, developer, tenantID, "sneaky@example.test", "Sneaky", ownerRole, "hash"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("developer inviting as owner = %v, want ErrNotFound", err)
	}
	if _, err := s.CreateRole(ctx, developer, tenantID, "shadow-owner", "Shadow", "",
		[]string{string(role.ReadConsole), string(role.ManageTenants)}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("developer creating an owner-grade role = %v, want ErrNotFound", err)
	}
	// Nor may they define any role at all: roles.manage is not theirs to hold,
	// however weak the role they were trying to mint.
	if _, err := s.CreateRole(ctx, developer, tenantID, "teammate", "Teammate", "",
		[]string{string(role.ReadConsole), string(role.ReadUsers)}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("developer creating any role = %v, want ErrNotFound", err)
	}
	// The developer can still maintain members using the roles already offered.
	if _, err := s.InviteUser(ctx, developer, tenantID, "teammate@example.test", "Teammate",
		systemRole(t, s, ctx, "viewer"), "hash"); err != nil {
		t.Fatalf("developer inviting a member: %v", err)
	}
}

func TestRolesManageIsRequiredToDefineRoles(t *testing.T) {
	s, ctx, _, developer, tenantID := rolesFixture(t)
	if _, err := s.ListRoles(ctx, developer, tenantID); err != nil {
		t.Fatalf("a developer may read the role catalog: %v", err)
	}
	if _, err := s.CreateRole(ctx, developer, tenantID, "nope", "Nope", "",
		[]string{string(role.ReadConsole)}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("developer creating a role = %v, want ErrNotFound", err)
	}
}

func TestAssignableRolesExcludeAnythingAboveTheActor(t *testing.T) {
	s, ctx, _, developer, tenantID := rolesFixture(t)
	assignable, err := s.AssignableRoles(ctx, developer, tenantID)
	if err != nil {
		t.Fatalf("assignable roles: %v", err)
	}
	ownerRole := systemRole(t, s, ctx, "owner")
	found := 0
	for _, item := range assignable {
		if !item.Assignable {
			t.Errorf("role %q was returned but is not marked assignable", item.Slug)
		}
		if contains(item.Permissions, string(role.ManageTenants)) {
			t.Errorf("developer may assign %q, which grants tenants.manage", item.Slug)
		}
		if item.ID == ownerRole {
			t.Error("a developer must not be offered the owner role")
		}
		found++
	}
	if found == 0 {
		t.Fatal("a developer should still be offered the roles within their authority")
	}
}

func TestUnknownPermissionIsRejectedWhenDefiningARole(t *testing.T) {
	s, ctx, owner, _, tenantID := rolesFixture(t)
	_, err := s.CreateRole(ctx, owner, tenantID, "sneaky", "Sneaky", "",
		[]string{string(role.ReadConsole), "superpower"})
	if err == nil {
		t.Fatal("a role must not be creatable with an unknown permission")
	}
}

func TestDuplicateRoleSlugIsRejected(t *testing.T) {
	s, ctx, owner, _, tenantID := rolesFixture(t)
	if _, err := s.CreateRole(ctx, owner, tenantID, "auditor", "Auditor", "",
		[]string{string(role.ReadConsole)}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	_, err := s.CreateRole(ctx, owner, tenantID, "auditor", "Another", "",
		[]string{string(role.ReadConsole)})
	if !errors.Is(err, store.ErrRoleSlugTaken) {
		t.Fatalf("duplicate slug = %v, want ErrRoleSlugTaken", err)
	}
}

// TestTenantKeepsAnOwner guards the demotion path: the last owner of a tenant
// must not be able to walk away from it and lock every administrator out.
func TestTenantKeepsAnOwner(t *testing.T) {
	s, ctx, owner, _, tenantID := rolesFixture(t)
	admin := addMember(t, s, ctx, owner, tenantID, "admin@example.test", "admin")
	adminRole := systemRole(t, s, ctx, "admin")
	ownerRole := systemRole(t, s, ctx, "owner")

	// The owner cannot simply step down while nobody else holds the role.
	if err := s.SetUserAccess(ctx, owner, tenantID, owner, adminRole, nil); !errors.Is(err, store.ErrLastOwner) {
		t.Fatalf("owner stepping down alone = %v, want ErrLastOwner", err)
	}
	// Handing the role over first makes the step down legal.
	if err := s.SetUserAccess(ctx, owner, tenantID, admin, ownerRole, nil); err != nil {
		t.Fatalf("promote the admin to owner: %v", err)
	}
	if err := s.SetUserAccess(ctx, admin, tenantID, owner, adminRole, nil); err != nil {
		t.Fatalf("step down once a second owner exists: %v", err)
	}
	// The admin is now the only owner and must not be able to walk away from it.
	if err := s.SetUserAccess(ctx, admin, tenantID, admin, adminRole, nil); !errors.Is(err, store.ErrLastOwner) {
		t.Fatalf("demoting the last owner = %v, want ErrLastOwner", err)
	}
}
