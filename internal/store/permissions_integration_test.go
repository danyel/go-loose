package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/danyel/go-loose/internal/role"
	"github.com/danyel/go-loose/internal/store"
)

func TestCatalogSeedsTheEnforcedPermissions(t *testing.T) {
	s, _, ctx := integrationStore(t)
	catalog, err := s.ListPermissions(ctx)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	if len(catalog) != len(role.Permissions()) {
		t.Fatalf("catalog has %d entries, want the %d seeded permissions", len(catalog), len(role.Permissions()))
	}
	for _, item := range catalog {
		if !item.System {
			t.Errorf("%q was not marked built in", item.Name)
		}
		if !item.Enforced {
			t.Errorf("%q is seeded but not reported as enforced", item.Name)
		}
		if item.Label == "" {
			t.Errorf("%q has no label", item.Name)
		}
	}
	// The order the role editor renders is most sensitive first.
	if catalog[0].Name != string(role.ManageTenants) {
		t.Errorf("catalog starts with %q, want %q", catalog[0].Name, role.ManageTenants)
	}
}

func TestTenantCanAddAPermissionAndGrantIt(t *testing.T) {
	s, _, ctx := integrationStore(t)
	owner := newUser(t, s, ctx, "owner@example.test")
	tenant := newTenant(t, s, ctx, owner, "nmbs").ID

	created, err := s.CreatePermission(ctx, owner, "reports.export", "Export reports", "Lets an app export reports.")
	if err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if created.System {
		t.Error("a permission added through the API must not be marked built in")
	}
	if created.Enforced {
		t.Error("a custom permission cannot be enforced by the console")
	}

	// It is immediately grantable, exactly like a built-in one.
	if _, err := s.CreateRole(ctx, owner, tenant, "reporter", "Reporter", "",
		[]string{string(role.ReadConsole), "reports.export"}); err != nil {
		t.Fatalf("grant a custom permission: %v", err)
	}

	catalog, err := s.ListPermissions(ctx)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	found := false
	for _, item := range catalog {
		if item.Name == "reports.export" {
			found = true
			if item.RoleCount != 1 {
				t.Errorf("role_count = %d, want 1", item.RoleCount)
			}
		}
	}
	if !found {
		t.Fatal("the new permission is missing from the catalog")
	}
}

func TestDeletingAPermissionInUseIsRefused(t *testing.T) {
	s, _, ctx := integrationStore(t)
	owner := newUser(t, s, ctx, "owner@example.test")
	tenant := newTenant(t, s, ctx, owner, "nmbs").ID

	if _, err := s.CreatePermission(ctx, owner, "reports.export", "Export reports", ""); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	reporter, err := s.CreateRole(ctx, owner, tenant, "reporter", "Reporter", "",
		[]string{string(role.ReadConsole), "reports.export"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := s.DeletePermission(ctx, owner, "reports.export"); !errors.Is(err, store.ErrPermissionInUse) {
		t.Fatalf("delete a granted permission = %v, want ErrPermissionInUse", err)
	}

	// Once no role grants it, the delete goes through.
	if _, err := s.UpdateRole(ctx, owner, reporter.ID, "Reporter", "",
		[]string{string(role.ReadConsole)}); err != nil {
		t.Fatalf("drop the custom permission: %v", err)
	}
	if err := s.DeletePermission(ctx, owner, "reports.export"); err != nil {
		t.Fatalf("delete an unused permission: %v", err)
	}
}

func TestBuiltInPermissionsCannotBeDeleted(t *testing.T) {
	s, _, ctx := integrationStore(t)
	owner := newUser(t, s, ctx, "owner@example.test")
	newTenant(t, s, ctx, owner, "nmbs")
	if err := s.DeletePermission(ctx, owner, string(role.ManageUsers)); !errors.Is(err, store.ErrPermissionSystem) {
		t.Fatalf("delete a built-in permission = %v, want ErrPermissionSystem", err)
	}
}

func TestDuplicateAndMalformedPermissionsAreRejected(t *testing.T) {
	s, _, ctx := integrationStore(t)
	owner := newUser(t, s, ctx, "owner@example.test")
	newTenant(t, s, ctx, owner, "nmbs")

	if _, err := s.CreatePermission(ctx, owner, "reports.export", "Export", ""); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if _, err := s.CreatePermission(ctx, owner, "reports.export", "Export again", ""); !errors.Is(err, store.ErrPermissionTaken) {
		t.Fatalf("duplicate permission = %v, want ErrPermissionTaken", err)
	}
	// A name the console already enforces cannot be redefined.
	if _, err := s.CreatePermission(ctx, owner, string(role.ManageUsers), "Manage", ""); !errors.Is(err, store.ErrPermissionTaken) {
		t.Fatalf("redefining a built-in = %v, want ErrPermissionTaken", err)
	}
	for _, name := range []string{"Reports.Export", "reports export", ".reports", "reports.", "", "ab"} {
		if _, err := s.CreatePermission(ctx, owner, name, "Label", ""); err == nil {
			t.Errorf("CreatePermission(%q) was accepted", name)
		}
	}
}

// TestOnlyOwnersMayChangeTheSharedCatalog guards the fact that the catalog is
// installation-wide: a developer who may maintain their own tenant's members
// must not be able to add a capability every tenant can then grant.
func TestOnlyOwnersMayChangeTheSharedCatalog(t *testing.T) {
	s, ctx, _, developer, _ := rolesFixture(t)
	if _, err := s.CreatePermission(ctx, developer, "reports.export", "Export reports", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("developer adding a permission = %v, want ErrNotFound", err)
	}
	if err := s.DeletePermission(ctx, developer, string(role.ReadConsole)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("developer deleting a permission = %v, want ErrNotFound", err)
	}
}

func TestARoleCannotGrantAPermissionThatIsNotInTheCatalog(t *testing.T) {
	s, ctx, owner, _, tenantID := rolesFixture(t)
	_, err := s.CreateRole(ctx, owner, tenantID, "sneaky", "Sneaky", "",
		[]string{string(role.ReadConsole), "not.in.the.catalog"})
	if !errors.Is(err, store.ErrUnknownPermission) {
		t.Fatalf("granting an unknown permission = %v, want ErrUnknownPermission", err)
	}
	// Nor can an existing role be edited to hold one.
	if _, err := s.UpdateRole(ctx, owner, mustSystemRole(t, s, ctx, "viewer"), "Viewer", "",
		[]string{string(role.ReadConsole), "not.in.the.catalog"}); !errors.Is(err, store.ErrUnknownPermission) {
		t.Fatalf("editing in an unknown permission = %v, want ErrUnknownPermission", err)
	}
}

// TestGrantingACustomPermissionNeedsTheRightAuthor documents the rule that makes
// the catalog usable without weakening the escalation guard. Whoever administers
// the catalog authored the permission, so they may pass it on even though nobody
// holds it yet; anybody else still needs to hold it first.
func TestGrantingACustomPermissionNeedsTheRightAuthor(t *testing.T) {
	s, ctx, owner, developer, tenantID := rolesFixture(t)
	if _, err := s.CreatePermission(ctx, owner, "reports.export", "Export reports", ""); err != nil {
		t.Fatalf("create permission: %v", err)
	}

	// The owner administers the catalog, so they can define a role granting it.
	// The role also carries users.manage so that whoever ends up holding it is
	// actually able to assign roles to somebody else.
	created, err := s.CreateRole(ctx, owner, tenantID, "reporter", "Reporter", "",
		[]string{string(role.ReadConsole), string(role.ManageUsers), "reports.export"})
	if err != nil {
		t.Fatalf("owner granting a custom permission: %v", err)
	}

	// A developer administers members but not the catalog, and does not hold the
	// permission, so they may not hand the role out.
	member := addMember(t, s, ctx, owner, tenantID, "victim@example.test", "viewer")
	if err := s.SetUserAccess(ctx, developer, tenantID, member, created.ID, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("developer assigning a role carrying an unheld custom permission = %v, want ErrNotFound", err)
	}
	// Nor may they mint an equivalent role of their own.
	if _, err := s.CreateRole(ctx, developer, tenantID, "rogue", "Rogue", "",
		[]string{string(role.ReadConsole), string(role.ManageUsers), "reports.export"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("developer minting a custom permission = %v, want ErrNotFound", err)
	}
	// A member who does hold it, and may manage members, may pass it on.
	reporter := addMember(t, s, ctx, owner, tenantID, "reporter@example.test", "viewer")
	if err := s.SetUserAccess(ctx, owner, tenantID, reporter, created.ID, nil); err != nil {
		t.Fatalf("owner assigning the role: %v", err)
	}
	if err := s.SetUserAccess(ctx, reporter, tenantID, member, created.ID, nil); err != nil {
		t.Fatalf("holder passing the permission on: %v", err)
	}

	// Holding the permission is not enough on its own: a role without
	// users.manage cannot assign anything.
	readonly, err := s.CreateRole(ctx, owner, tenantID, "readonly-reporter", "Read only reporter", "",
		[]string{string(role.ReadConsole), "reports.export"})
	if err != nil {
		t.Fatalf("create read-only role: %v", err)
	}
	if err := s.SetUserAccess(ctx, owner, tenantID, reporter, mustSystemRole(t, s, ctx, "viewer"), nil); err != nil {
		t.Fatalf("move the reporter aside: %v", err)
	}
	if err := s.SetUserAccess(ctx, reporter, tenantID, member, readonly.ID, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("assigning without users.manage = %v, want ErrNotFound", err)
	}
}

func mustSystemRole(t *testing.T, s *store.Store, ctx context.Context, slug string) string {
	t.Helper()
	id, err := s.SystemRoleID(ctx, slug)
	if err != nil {
		t.Fatalf("look up %q: %v", slug, err)
	}
	return id
}
