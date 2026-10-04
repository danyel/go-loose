package role

import (
	"slices"
	"strings"
	"testing"
)

func TestParseRejectsUnknownPermissions(t *testing.T) {
	valid := []string{
		"console.read", "users.read", "applications.manage", "keys.manage",
		"contracts.manage", "users.manage", "roles.manage", "tenants.manage",
		"profile.edit",
	}
	for _, value := range valid {
		if _, ok := Parse(value); !ok {
			t.Errorf("Parse(%q) = not ok, want a permission", value)
		}
	}
	for _, value := range []string{"", "Console.read", "console", "superuser", "users.manage; DROP TABLE roles"} {
		if parsed, ok := Parse(value); ok {
			t.Errorf("Parse(%q) = %q, want rejection", value, parsed)
		}
	}
}

func TestValidMatchesParse(t *testing.T) {
	for _, permission := range Permissions() {
		if !permission.Valid() {
			t.Errorf("%q reports itself invalid", permission)
		}
		if parsed, ok := Parse(string(permission)); !ok || parsed != permission {
			t.Errorf("Parse(%q) did not round-trip", permission)
		}
	}
	if Permission("nope").Valid() {
		t.Error("an unknown permission reports itself valid")
	}
}

func TestPermissionsAreDottedNames(t *testing.T) {
	for _, permission := range Permissions() {
		name := string(permission)
		if len(name) < 3 || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
			t.Fatalf("%q is not a plausible permission name", name)
		}
		dot := false
		for _, character := range name {
			switch {
			case character == '.':
				dot = true
			case character >= 'a' && character <= 'z', character >= '0' && character <= '9', character == '-':
			default:
				t.Fatalf("%q contains %q; permissions use lowercase words", name, character)
			}
		}
		if !dot {
			t.Errorf("%q should be a namespaced name", name)
		}
	}
}

func TestCatalogDescribesEveryPermission(t *testing.T) {
	catalog := Catalog()
	if len(catalog) != len(Permissions()) {
		t.Fatalf("catalog has %d entries, want %d", len(catalog), len(Permissions()))
	}
	seen := make(map[string]bool, len(catalog))
	for _, entry := range catalog {
		if entry.Value == "" || entry.Label == "" || entry.Description == "" {
			t.Errorf("incomplete catalog entry %+v", entry)
		}
		if seen[entry.Value] {
			t.Errorf("permission %q appears twice in the catalog", entry.Value)
		}
		seen[entry.Value] = true
	}
}

// TestCatalogFollowsDisplayOrder guards the order the console renders the
// permission checkboxes in: the most sensitive capability first.
func TestCatalogFollowsDisplayOrder(t *testing.T) {
	catalog := Catalog()
	want := []string{"tenants.manage", "roles.manage", "users.manage"}
	for index, value := range want {
		if catalog[index].Value != value {
			t.Errorf("catalog[%d] = %q, want %q", index, catalog[index].Value, value)
		}
	}
}

func TestPermissionsReturnsACopy(t *testing.T) {
	first := Permissions()
	if len(first) == 0 {
		t.Fatal("no permissions")
	}
	first[0] = "mutated"
	if Permissions()[0] == "mutated" {
		t.Error("Permissions exposed its backing array")
	}
}

func TestValuesMatchesPermissions(t *testing.T) {
	values := Values()
	permissions := Permissions()
	if len(values) != len(permissions) {
		t.Fatalf("Values has %d entries, want %d", len(values), len(permissions))
	}
	for index, permission := range permissions {
		if values[index] != string(permission) {
			t.Errorf("Values()[%d] = %q, want %q", index, values[index], permission)
		}
	}
	if !slices.Contains(values, string(ManageUsers)) {
		t.Error("users.manage is missing from Values")
	}
}
