package store_test

import (
	"errors"
	"testing"

	"github.com/danyel/go-loose/internal/store"
)

// TestSystemAdministratorIsNotAutomaticallyInsideTenantApplications pins the
// boundary between the management plane and the client plane.
//
// Owning every tenant is what lets the first administrator reach the whole
// installation from the console. It is not permission to sign in to the
// applications running inside those tenants: ClientForAuthorization answers for a
// user_application_access row and nothing else, so a claim that inserted one per
// application would ship every installation with a standing administrator
// account inside every customer application. Access to an application is an
// explicit grant, and this test also pins that such a grant is still possible on
// purpose, because an administrator is allowed to attach themselves.
func TestSystemAdministratorIsNotAutomaticallyInsideTenantApplications(t *testing.T) {
	s, _, ctx := integrationStore(t)

	// Two tenants, each with a client configured, so that "every application" is
	// not satisfied by a single row.
	firstOwner := newUser(t, s, ctx, "first@example.test")
	first := newTenant(t, s, ctx, firstOwner, "nmbs")
	secondOwner := newUser(t, s, ctx, "second@example.test")
	second := newTenant(t, s, ctx, secondOwner, "ypto")

	const redirect = "https://app.example.test/callback"
	application := func(owner, tenantID, slug string) store.Application {
		t.Helper()
		created, err := s.CreateApplication(ctx, owner, store.Application{
			TenantID: tenantID, Slug: slug, Name: slug, AllowedHosts: []string{},
		})
		if err != nil {
			t.Fatalf("create application %s: %v", slug, err)
		}
		if _, err := s.ConfigureClient(ctx, owner, created.ID, []string{redirect}, secretHash(slug)); err != nil {
			t.Fatalf("configure client login for %s: %v", slug, err)
		}
		return created
	}
	firstApp := application(firstOwner, first.ID, "guess")
	secondApp := application(secondOwner, second.ID, "tell")

	admin := newUser(t, s, ctx, "admin@example.test")
	claimed, err := s.ClaimFirstSystemAdministrator(ctx, admin)
	if err != nil {
		t.Fatalf("claim first system administrator: %v", err)
	}
	if !claimed {
		t.Fatal("the first user to sign in must become the system administrator")
	}

	// The management plane still reaches everything: the claim owns both tenants,
	// which is what the console needs to administer them.
	console, err := s.HasConsoleAccess(ctx, admin)
	if err != nil {
		t.Fatalf("HasConsoleAccess: %v", err)
	}
	if !console {
		t.Error("a system administrator must have console access")
	}
	tenants, err := s.ListTenants(ctx, admin)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(tenants) != 2 {
		t.Errorf("the administrator owns %d tenants, want 2", len(tenants))
	}

	// The client plane does not. No application was granted, so neither endpoint
	// that mints or resolves a hosted-login session will recognize them.
	for _, test := range []struct {
		name        string
		application store.Application
	}{
		{name: "nmbs", application: firstApp},
		{name: "ypto", application: secondApp},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := s.ClientForAuthorization(ctx, test.application.ClientID, redirect, admin); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("ClientForAuthorization = %v, want ErrNotFound: owning a tenant must not open its applications", err)
			}
			if _, err := s.ClientUserByToken(ctx, secretHash("no-session")); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("ClientUserByToken = %v, want ErrNotFound", err)
			}
		})
	}

	// Attaching the administrator to one application is allowed, and it is the only
	// way in. They hold users.manage in every tenant by virtue of owning it, which
	// is what makes the deliberate act possible.
	ownerRole, err := s.SystemRoleID(ctx, "owner")
	if err != nil {
		t.Fatalf("look up the owner role: %v", err)
	}
	if err := s.SetUserAccess(ctx, admin, first.ID, admin, ownerRole, []string{firstApp.ID}); err != nil {
		t.Fatalf("an administrator must be able to attach themselves to an application: %v", err)
	}
	if _, err := s.ClientForAuthorization(ctx, firstApp.ClientID, redirect, admin); err != nil {
		t.Fatalf("ClientForAuthorization after an explicit grant = %v, want the application", err)
	}

	// Withdrawing it takes effect immediately and leaves the console untouched.
	if err := s.SetUserAccess(ctx, admin, first.ID, admin, ownerRole, nil); err != nil {
		t.Fatalf("withdraw the grant: %v", err)
	}
	if _, err := s.ClientForAuthorization(ctx, firstApp.ClientID, redirect, admin); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ClientForAuthorization after withdrawal = %v, want ErrNotFound", err)
	}
	console, err = s.HasConsoleAccess(ctx, admin)
	if err != nil {
		t.Fatalf("HasConsoleAccess: %v", err)
	}
	if !console {
		t.Error("withdrawing an application grant must not cost the administrator their console")
	}
}
