package role

import (
	"slices"
	"strings"
	"testing"
)

func TestParseRejectsUnknownRoles(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "owner", want: true},
		{value: "admin", want: true},
		{value: "developer", want: true},
		{value: "operator", want: true},
		{value: "viewer", want: true},
		{value: "user", want: true},
		{value: "Owner", want: false},
		{value: "", want: false},
		{value: "superuser", want: false},
		{value: "owner; DROP TABLE memberships", want: false},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			_, ok := Parse(test.value)
			if ok != test.want {
				t.Fatalf("Parse(%q) ok = %v, want %v", test.value, ok, test.want)
			}
		})
	}
}

func TestPermissionMatrix(t *testing.T) {
	tests := []struct {
		role       Role
		permission Permission
		want       bool
	}{
		{role: Owner, permission: ManageTenants, want: true},
		{role: Owner, permission: ManageUsers, want: true},
		{role: Admin, permission: ManageTenants, want: false},
		{role: Admin, permission: ManageUsers, want: true},
		{role: Admin, permission: ManageApplications, want: true},
		{role: Developer, permission: ManageUsers, want: false},
		{role: Developer, permission: ManageApplications, want: true},
		{role: Developer, permission: ManageKeys, want: true},
		{role: Developer, permission: ManageContracts, want: true},
		{role: Operator, permission: ManageApplications, want: false},
		{role: Operator, permission: ManageKeys, want: true},
		{role: Operator, permission: ManageContracts, want: true},
		{role: Viewer, permission: ManageKeys, want: false},
		{role: Viewer, permission: ReadConsole, want: true},
		{role: User, permission: ReadConsole, want: false},
		{role: User, permission: ReadUsers, want: false},
		{role: User, permission: EditProfile, want: true},
	}
	for _, test := range tests {
		t.Run(string(test.role)+"/"+string(test.permission), func(t *testing.T) {
			if got := test.role.Allows(test.permission); got != test.want {
				t.Fatalf("Allows(%q) = %v, want %v", test.permission, got, test.want)
			}
		})
	}
}

func TestEveryRoleCanEditItsOwnProfile(t *testing.T) {
	for _, item := range All() {
		if !item.Allows(EditProfile) {
			t.Fatalf("role %q cannot edit its own profile", item)
		}
	}
}

func TestGrantsMatchAllows(t *testing.T) {
	for _, permission := range ordered {
		granted := Grants(permission)
		for _, item := range All() {
			if slices.Contains(granted, string(item)) != item.Allows(permission) {
				t.Fatalf("Grants(%q) and Allows disagree for role %q", permission, item)
			}
		}
	}
}

func TestGrantsListsRolesInPrivilegeOrder(t *testing.T) {
	if got := Grants(ManageKeys); !slices.Equal(got, []string{"owner", "admin", "developer", "operator"}) {
		t.Fatalf("Grants(ManageKeys) = %v", got)
	}
	if got := Grants(ManageUsers); !slices.Equal(got, []string{"owner", "admin"}) {
		t.Fatalf("Grants(ManageUsers) = %v", got)
	}
	if got := Grants(ReadConsole); !slices.Contains(got, string(Owner)) || slices.Contains(got, string(User)) {
		t.Fatalf("Grants(ReadConsole) = %v", got)
	}
}

func TestCatalogCoversEveryRoleWithALabel(t *testing.T) {
	entries := Catalog()
	if len(entries) != len(catalog) {
		t.Fatalf("Catalog() length = %d, want %d", len(entries), len(catalog))
	}
	for _, entry := range entries {
		if entry.Label == "" {
			t.Fatalf("role %q has no label", entry.Value)
		}
		parsed, ok := Parse(entry.Value)
		if !ok {
			t.Fatalf("catalog entry %q is not a known role", entry.Value)
		}
		if len(entry.Permissions) != len(parsed.Permissions()) {
			t.Fatalf("role %q catalog permissions drifted from the matrix", entry.Value)
		}
	}
}

func TestGrantableExcludesOwner(t *testing.T) {
	for _, item := range Grantable() {
		if item == Owner {
			t.Fatal("owner must not be grantable through an invitation")
		}
	}
	if len(GrantableValues()) != len(catalog)-1 {
		t.Fatalf("GrantableValues() length = %d", len(GrantableValues()))
	}
}

func TestPermissionsUseDottedNames(t *testing.T) {
	for _, permission := range All()[0].Permissions() {
		if !strings.Contains(permission, ".") {
			t.Fatalf("permission %q should be a dotted capability name", permission)
		}
	}
}
