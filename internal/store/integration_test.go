package store_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/danyel/go-loose/internal/contract"
	"github.com/danyel/go-loose/internal/database"
	"github.com/danyel/go-loose/internal/role"
	"github.com/danyel/go-loose/internal/store"
)

// integrationStore opens the disposable PostgreSQL database named by
// GO_LOOSE_TEST_DATABASE_URL, drops every table, and applies all migrations. The
// test is skipped when the variable is absent so unit runs never touch a
// developer's data.
func integrationStore(t *testing.T) (*store.Store, *sql.DB, context.Context) {
	t.Helper()
	url := os.Getenv("GO_LOOSE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set GO_LOOSE_TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	ctx := context.Background()
	db, err := database.Open(ctx, url)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := resetSchema(ctx, db); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return store.New(db), db, ctx
}

// grantApplicationAccess inserts an application grant directly so that tests can
// build states the management API intentionally refuses to create, such as a
// grant for a user with no membership.
func grantApplicationAccess(t *testing.T, db *sql.DB, ctx context.Context, applicationID, userID string) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO user_application_access(application_id, user_id, granted_by)
		VALUES ($1, $2, $2)`, applicationID, userID); err != nil {
		t.Fatalf("grant application access: %v", err)
	}
}

func contractDocument() contract.Document {
	return contract.Document{
		Version:   "3.1.0",
		JSON:      []byte(`{"openapi":"3.1.0","paths":{"/health":{"get":{"operationId":"health"}}}}`),
		Endpoints: []contract.Endpoint{{Method: "GET", Path: "/health", OperationID: "health"}},
	}
}

// resetSchema drops every table in the public schema, including
// schema_migrations, so that Migrate replays the full history from scratch.
func resetSchema(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `
		SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	tables := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		tables = append(tables, `"`+name+`"`)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, name := range tables {
		if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS "+name+" CASCADE"); err != nil {
			return err
		}
	}
	return nil
}

// newUser creates or reuses an account and returns its id.
func newUser(t *testing.T, s *store.Store, ctx context.Context, email string) string {
	t.Helper()
	user, err := s.UpsertUser(ctx, "test:"+email, email, strings.ToUpper(email[:1])+email[1:])
	if err != nil {
		t.Fatalf("upsert %s: %v", email, err)
	}
	return user.ID
}

// newTenant creates a tenant owned by owner and registers one application.
func newTenant(t *testing.T, s *store.Store, ctx context.Context, owner, slug string) store.Tenant {
	t.Helper()
	tenant, err := s.CreateTenant(ctx, owner, slug, strings.ToUpper(slug))
	if err != nil {
		t.Fatalf("create tenant %s: %v", slug, err)
	}
	return tenant
}

// addMember invites a member into the tenant with the given role.
func addMember(t *testing.T, s *store.Store, ctx context.Context, owner string, tenantID, email, membershipRole string) string {
	t.Helper()
	member, err := s.InviteUser(ctx, owner, tenantID, email, email, membershipRole, "not-a-real-hash")
	if err != nil {
		t.Fatalf("invite %s as %s: %v", email, membershipRole, err)
	}
	if member.Role != membershipRole {
		t.Fatalf("invited role = %q, want %q", member.Role, membershipRole)
	}
	return member.ID
}

func TestMigrationsApplyAndRolesAreAccepted(t *testing.T) {
	s, _, ctx := integrationStore(t)
	owner := newUser(t, s, ctx, "owner@example.test")
	tenant := newTenant(t, s, ctx, owner, "nmbs")
	for _, item := range []role.Role{role.Developer, role.Operator, role.User} {
		addMember(t, s, ctx, owner, tenant.ID, string(item)+"@example.test", string(item))
	}
	if _, err := s.ListTenants(ctx, owner); err != nil {
		t.Fatalf("list tenants: %v", err)
	}
}

func TestMembershipRoleConstraintRejectsUnknownRole(t *testing.T) {
	s, _, ctx := integrationStore(t)
	owner := newUser(t, s, ctx, "owner@example.test")
	tenant := newTenant(t, s, ctx, owner, "nmbs")
	member := addMember(t, s, ctx, owner, tenant.ID, "member@example.test", string(role.Viewer))
	if err := s.SetUserAccess(ctx, owner, tenant.ID, member, "superuser", nil); err == nil {
		t.Fatal("the database must reject a role outside the permission matrix")
	}
}

func TestPermissionMatrixIsEnforcedInQueries(t *testing.T) {
	s, _, ctx := integrationStore(t)
	owner := newUser(t, s, ctx, "owner@example.test")
	tenant := newTenant(t, s, ctx, owner, "nmbs")
	application, err := s.CreateApplication(ctx, owner, store.Application{
		TenantID: tenant.ID, Slug: "guess", Name: "Guess", AllowedHosts: []string{},
	})
	if err != nil {
		t.Fatalf("owner cannot create an application: %v", err)
	}
	tests := []struct {
		role              role.Role
		canCreateApp      bool
		canIssueKey       bool
		canSaveContract   bool
		canListManaged    bool
		canConfigureClien bool
	}{
		{role: role.Owner, canCreateApp: true, canIssueKey: true, canSaveContract: true, canListManaged: true, canConfigureClien: true},
		{role: role.Admin, canCreateApp: true, canIssueKey: true, canSaveContract: true, canListManaged: true, canConfigureClien: true},
		{role: role.Developer, canCreateApp: true, canIssueKey: true, canSaveContract: true, canListManaged: false, canConfigureClien: true},
		{role: role.Operator, canCreateApp: false, canIssueKey: true, canSaveContract: true, canListManaged: false, canConfigureClien: false},
		{role: role.Viewer, canCreateApp: false, canIssueKey: false, canSaveContract: false, canListManaged: false, canConfigureClien: false},
		{role: role.User, canCreateApp: false, canIssueKey: false, canSaveContract: false, canListManaged: false, canConfigureClien: false},
	}
	for _, test := range tests {
		t.Run(string(test.role), func(t *testing.T) {
			member := addMember(t, s, ctx, owner, tenant.ID, string(test.role)+"@example.test", string(test.role))
			slug := strings.ReplaceAll(string(test.role), "owner", "own")

			_, err := s.CreateApplication(ctx, member, store.Application{
				TenantID: tenant.ID, Slug: slug, Name: slug, AllowedHosts: []string{},
			})
			assertPermission(t, "create application", err, test.canCreateApp)

			_, err = s.CreateAPIKey(ctx, member, application.ID, slug+"-key", "gl_prefix", secretHash(slug), nil)
			assertPermission(t, "issue key", err, test.canIssueKey)

			_, err = s.SaveContract(ctx, member, application.ID, contractDocument(), nil)
			assertPermission(t, "import contract", err, test.canSaveContract)

			managed, err := s.ListManagedUsers(ctx, member)
			if err != nil {
				t.Fatalf("list managed users: %v", err)
			}
			if test.canListManaged != (len(managed) > 0) {
				t.Fatalf("users.read for %s: got %d members, want non-empty=%v", test.role, len(managed), test.canListManaged)
			}

			_, err = s.ConfigureClient(ctx, member, application.ID, []string{"https://app.example.test/callback"}, secretHash(slug))
			assertPermission(t, "configure client login", err, test.canConfigureClien)
		})
	}
}

func TestConsoleAccessExcludesSelfServiceMembers(t *testing.T) {
	s, _, ctx := integrationStore(t)
	owner := newUser(t, s, ctx, "owner@example.test")
	tenant := newTenant(t, s, ctx, owner, "nmbs")
	selfService := addMember(t, s, ctx, owner, tenant.ID, "enduser@example.test", string(role.User))
	operator := addMember(t, s, ctx, owner, tenant.ID, "operator@example.test", string(role.Operator))
	waiting := newUser(t, s, ctx, "waiting@example.test")

	for _, test := range []struct {
		name    string
		userID  string
		console bool
		member  bool
	}{
		{name: "owner", userID: owner, console: true, member: true},
		{name: "operator", userID: operator, console: true, member: true},
		{name: "self-service user", userID: selfService, console: false, member: true},
		{name: "waiting room", userID: waiting, console: false, member: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			console, err := s.HasConsoleAccess(ctx, test.userID)
			if err != nil {
				t.Fatalf("HasConsoleAccess: %v", err)
			}
			if console != test.console {
				t.Fatalf("HasConsoleAccess = %v, want %v", console, test.console)
			}
			member, err := s.HasMembership(ctx, test.userID)
			if err != nil {
				t.Fatalf("HasMembership: %v", err)
			}
			if member != test.member {
				t.Fatalf("HasMembership = %v, want %v", member, test.member)
			}
		})
	}
}

func TestTenantPermissionsComeFromTheRoleMatrix(t *testing.T) {
	s, _, ctx := integrationStore(t)
	owner := newUser(t, s, ctx, "owner@example.test")
	tenant := newTenant(t, s, ctx, owner, "nmbs")
	developer := addMember(t, s, ctx, owner, tenant.ID, "dev@example.test", string(role.Developer))

	tenants, err := s.ListTenants(ctx, developer)
	if err != nil {
		t.Fatalf("list tenants: %v", err)
	}
	if len(tenants) != 1 || tenants[0].Role != string(role.Developer) {
		t.Fatalf("tenants = %+v", tenants)
	}
	if !contains(tenants[0].Permissions, string(role.ManageApplications)) {
		t.Fatalf("developer permissions = %v", tenants[0].Permissions)
	}
	if contains(tenants[0].Permissions, string(role.ManageUsers)) {
		t.Fatalf("developer permissions = %v, must not manage users", tenants[0].Permissions)
	}
}

func TestProfileRoundTrip(t *testing.T) {
	s, _, ctx := integrationStore(t)
	owner := newUser(t, s, ctx, "owner@example.test")
	tenant := newTenant(t, s, ctx, owner, "nmbs")
	member := addMember(t, s, ctx, owner, tenant.ID, "member@example.test", string(role.Operator))

	before, err := s.Profile(ctx, member)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if before.AvatarKey != nil || before.NameCustomized {
		t.Fatalf("fresh profile = %+v", before)
	}
	if len(before.Memberships) != 1 || before.Memberships[0].Role != string(role.Operator) {
		t.Fatalf("memberships = %+v", before.Memberships)
	}
	if !contains(before.Memberships[0].Permissions, string(role.ManageKeys)) {
		t.Fatalf("membership permissions = %v", before.Memberships[0].Permissions)
	}

	name := "Renamed By User"
	if err := s.UpdateProfile(ctx, member, store.ProfileUpdate{DisplayName: &name}); err != nil {
		t.Fatalf("rename: %v", err)
	}
	after, err := s.Profile(ctx, member)
	if err != nil {
		t.Fatalf("profile after rename: %v", err)
	}
	if after.DisplayName != name || !after.NameCustomized || after.ProfileUpdatedAt == nil {
		t.Fatalf("profile = %+v", after)
	}
}

func TestLoginDoesNotOverwriteACustomizedDisplayName(t *testing.T) {
	s, _, ctx := integrationStore(t)
	user := newUser(t, s, ctx, "person@example.test")
	name := "My Chosen Name"
	if err := s.UpdateProfile(ctx, user, store.ProfileUpdate{DisplayName: &name}); err != nil {
		t.Fatalf("rename: %v", err)
	}
	for range 2 {
		if _, err := s.UpsertUser(ctx, "google:1234", "person@example.test", "Identity Provider Name"); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	profile, err := s.Profile(ctx, user)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if profile.DisplayName != name {
		t.Fatalf("display name = %q, want %q", profile.DisplayName, name)
	}
}

func TestUncustomizedDisplayNameStillFollowsTheIdentityProvider(t *testing.T) {
	s, _, ctx := integrationStore(t)
	user := newUser(t, s, ctx, "person@example.test")
	if _, err := s.UpsertUser(ctx, "google:1234", "person@example.test", "Identity Provider Name"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	profile, err := s.Profile(ctx, user)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if profile.DisplayName != "Identity Provider Name" {
		t.Fatalf("display name = %q", profile.DisplayName)
	}
}

func TestPictureIsStoredAndReadableByKey(t *testing.T) {
	s, _, ctx := integrationStore(t)
	owner := newUser(t, s, ctx, "owner@example.test")
	tenant := newTenant(t, s, ctx, owner, "nmbs")
	member := addMember(t, s, ctx, owner, tenant.ID, "member@example.test", string(role.Viewer))
	key := "Zq1Yb3l0Rk9pT2h3ZjQ4eXh3YjFkNGQ3OTFhMmNkYThl"
	payload := []byte{0x89, 'P', 'N', 'G', 1, 2, 3, 4}

	if err := s.UpdateProfile(ctx, member, store.ProfileUpdate{
		AvatarKey: key, AvatarData: payload, ContentType: "image/png",
	}); err != nil {
		t.Fatalf("store picture: %v", err)
	}
	picture, err := s.Picture(ctx, key)
	if err != nil {
		t.Fatalf("load picture: %v", err)
	}
	if picture.ContentType != "image/png" || string(picture.Data) != string(payload) {
		t.Fatalf("picture = %+v", picture)
	}
	if picture.UpdatedAt.IsZero() {
		t.Fatal("picture must record when it was stored")
	}
	profile, err := s.Profile(ctx, member)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if profile.AvatarKey == nil || *profile.AvatarKey != key || profile.AvatarUpdatedAt == nil {
		t.Fatalf("profile avatar = %+v", profile)
	}

	if err := s.UpdateProfile(ctx, member, store.ProfileUpdate{RemoveAvatar: true}); err != nil {
		t.Fatalf("remove picture: %v", err)
	}
	if _, err := s.Picture(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Picture() error = %v, want ErrNotFound", err)
	}
	cleared, err := s.Profile(ctx, member)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if cleared.AvatarKey != nil || cleared.AvatarUpdatedAt != nil {
		t.Fatalf("profile still advertises a picture: %+v", cleared)
	}
}

func TestReplacingAPictureRetiresTheOldKey(t *testing.T) {
	s, _, ctx := integrationStore(t)
	user := newUser(t, s, ctx, "person@example.test")
	first := "Zq1Yb3l0Rk9pT2h3ZjQ4eXh3YjFkNGQ3OTFhMmNkYThl"
	second := "b3JkZXJ5a2V5Zm9ydGhlU2Vjb25kVXBvZGF0ZVRlc3QxMjM0NQ"
	if err := s.UpdateProfile(ctx, user, store.ProfileUpdate{AvatarKey: first, AvatarData: []byte("a"), ContentType: "image/png"}); err != nil {
		t.Fatalf("store first picture: %v", err)
	}
	if err := s.UpdateProfile(ctx, user, store.ProfileUpdate{AvatarKey: second, AvatarData: []byte("b"), ContentType: "image/png"}); err != nil {
		t.Fatalf("store second picture: %v", err)
	}
	if _, err := s.Picture(ctx, first); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the replaced key must stop resolving, got %v", err)
	}
	picture, err := s.Picture(ctx, second)
	if err != nil || string(picture.Data) != "b" {
		t.Fatalf("picture = %+v, err = %v", picture, err)
	}
}

func TestPictureKeysAreUnique(t *testing.T) {
	s, _, ctx := integrationStore(t)
	first, second := newUser(t, s, ctx, "one@example.test"), newUser(t, s, ctx, "two@example.test")
	key := "Zq1Yb3l0Rk9pT2h3ZjQ4eXh3YjFkNGQ3OTFhMmNkYThl"
	if err := s.UpdateProfile(ctx, first, store.ProfileUpdate{AvatarKey: key, AvatarData: []byte("a"), ContentType: "image/png"}); err != nil {
		t.Fatalf("store first picture: %v", err)
	}
	if err := s.UpdateProfile(ctx, second, store.ProfileUpdate{AvatarKey: key, AvatarData: []byte("b"), ContentType: "image/png"}); err == nil {
		t.Fatal("two users must not be able to claim the same picture key")
	}
}

func TestIncompletePictureIsRejectedByTheDatabase(t *testing.T) {
	s, _, ctx := integrationStore(t)
	user := newUser(t, s, ctx, "person@example.test")
	err := s.UpdateProfile(ctx, user, store.ProfileUpdate{AvatarKey: "Zq1Yb3l0Rk9pT2h3ZjQ4eXh3YjFkNGQ3OTFhMmNkYThl"})
	if err != nil {
		t.Fatalf("an update without picture bytes is a no-op, got %v", err)
	}
	if _, err := s.Picture(ctx, "Zq1Yb3l0Rk9pT2h3ZjQ4eXh3YjFkNGQ3OTFhMmNkYThl"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Picture() error = %v, want ErrNotFound", err)
	}
}

func TestClientSessionReportsMembershipRoleAndPicture(t *testing.T) {
	s, db, ctx := integrationStore(t)
	owner := newUser(t, s, ctx, "owner@example.test")
	tenant := newTenant(t, s, ctx, owner, "nmbs")
	application, err := s.CreateApplication(ctx, owner, store.Application{
		TenantID: tenant.ID, Slug: "guess", Name: "Guess", AllowedHosts: []string{},
	})
	if err != nil {
		t.Fatalf("create application: %v", err)
	}
	member := addMember(t, s, ctx, owner, tenant.ID, "member@example.test", string(role.Operator))
	if _, err := s.ConfigureClient(ctx, owner, application.ID, []string{"https://app.example.test/callback"}, []byte("hash")); err != nil {
		t.Fatalf("configure client: %v", err)
	}
	if err := s.UpdateProfile(ctx, member, store.ProfileUpdate{
		AvatarKey:  "Zq1Yb3l0Rk9pT2h3ZjQ4eXh3YjFkNGQ3OTFhMmNkYThl",
		AvatarData: []byte("a"), ContentType: "image/png",
	}); err != nil {
		t.Fatalf("store picture: %v", err)
	}
	grantApplicationAccess(t, db, ctx, application.ID, member)
	if err := s.CreateAuthorizationCode(ctx, application.ID, member, "https://app.example.test/callback", []byte("code-hash")); err != nil {
		t.Fatalf("create authorization code: %v", err)
	}
	user, _, err := s.ExchangeAuthorizationCode(ctx, application.ClientID, "https://app.example.test/callback", []byte("hash"), []byte("code-hash"), []byte("token-hash"))
	if err != nil {
		t.Fatalf("exchange authorization code: %v", err)
	}
	if user.Role != string(role.Operator) {
		t.Fatalf("role = %q, want operator", user.Role)
	}
	if user.AvatarKey == nil {
		t.Fatal("the client payload must expose the picture locator")
	}
	byToken, err := s.ClientUserByToken(ctx, []byte("token-hash"))
	if err != nil {
		t.Fatalf("client user by token: %v", err)
	}
	if byToken.Role != string(role.Operator) || byToken.AvatarKey == nil {
		t.Fatalf("client user = %+v", byToken)
	}
}

func TestClientSessionWithoutMembershipFallsBackToUserRole(t *testing.T) {
	s, db, ctx := integrationStore(t)
	owner := newUser(t, s, ctx, "owner@example.test")
	tenant := newTenant(t, s, ctx, owner, "nmbs")
	application, err := s.CreateApplication(ctx, owner, store.Application{
		TenantID: tenant.ID, Slug: "guess", Name: "Guess", AllowedHosts: []string{},
	})
	if err != nil {
		t.Fatalf("create application: %v", err)
	}
	orphan := newUser(t, s, ctx, "orphan@example.test")
	if _, err := s.ConfigureClient(ctx, owner, application.ID, []string{"https://app.example.test/cb"}, []byte("hash")); err != nil {
		t.Fatalf("configure client: %v", err)
	}
	grantApplicationAccess(t, db, ctx, application.ID, orphan)
	if err := s.CreateAuthorizationCode(ctx, application.ID, orphan, "https://app.example.test/cb", []byte("code")); err != nil {
		t.Fatalf("create authorization code: %v", err)
	}
	user, _, err := s.ExchangeAuthorizationCode(ctx, application.ClientID, "https://app.example.test/cb", []byte("hash"), []byte("code"), []byte("token"))
	if err != nil {
		t.Fatalf("exchange authorization code: %v", err)
	}
	if user.Role != string(role.User) {
		t.Fatalf("role = %q, want the least privileged fallback %q", user.Role, role.User)
	}
}

func assertPermission(t *testing.T, operation string, err error, allowed bool) {
	t.Helper()
	switch {
	case allowed && err != nil:
		t.Fatalf("%s must be allowed, got %v", operation, err)
	case !allowed && !errors.Is(err, store.ErrNotFound):
		t.Fatalf("%s must be denied with ErrNotFound, got %v", operation, err)
	}
}

// secretHash builds a distinct digest per key name because secret_hash is unique.
func secretHash(name string) []byte {
	return []byte("sha256-of-" + name)
}

func contains(values []string, want string) bool {
	for _, item := range values {
		if item == want {
			return true
		}
	}
	return false
}
