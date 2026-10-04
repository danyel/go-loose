// Package role defines the permission vocabulary that authorizes console and
// management behavior.
//
// Roles are rows in the roles table and their permissions live in
// role_permissions, so a tenant can define its own and authorization is
// resolved by the database rather than from a matrix held here. What belongs in
// this package is the closed set of permissions a role may be granted, plus the
// labels the console renders.
//
// Keep the permission list in step with the role_permissions_permission_check
// constraint in migration 0006: a name that is not in both places cannot be
// stored.
package role

// Permission is a capability granted by a role.
type Permission string

const (
	// ReadConsole opens the management console. Self-service members lack it so
	// that they are routed to their profile instead.
	ReadConsole Permission = "console.read"
	// ReadUsers lists a tenant's members and their roles.
	ReadUsers Permission = "users.read"
	// ManageApplications registers applications and configures their client
	// credentials.
	ManageApplications Permission = "applications.manage"
	// ManageKeys issues and revokes API keys.
	ManageKeys Permission = "keys.manage"
	// ManageContracts imports OpenAPI contracts.
	ManageContracts Permission = "contracts.manage"
	// ManageUsers invites members and changes the roles and application grants
	// of existing ones.
	ManageUsers Permission = "users.manage"
	// ManageRoles creates and edits the tenant's own roles. Kept separate from
	// ManageUsers because defining roles is what defines privilege.
	ManageRoles Permission = "roles.manage"
	// ManageTenants creates tenants and administers the installation.
	ManageTenants Permission = "tenants.manage"
	// EditProfile changes one's own display name and picture.
	EditProfile Permission = "profile.edit"
)

// ordered lists every permission from most to least sensitive. The order is the
// one the console renders checkboxes in.
var ordered = []Permission{
	ManageTenants,
	ManageRoles,
	ManageUsers,
	ManageApplications,
	ManageKeys,
	ManageContracts,
	ReadUsers,
	ReadConsole,
	EditProfile,
}

var known = map[Permission]bool{
	ReadConsole:        true,
	ReadUsers:          true,
	ManageApplications: true,
	ManageKeys:         true,
	ManageContracts:    true,
	ManageUsers:        true,
	ManageRoles:        true,
	ManageTenants:      true,
	EditProfile:        true,
}

// Entry describes a permission for the console and for API clients.
type Entry struct {
	Value       string `json:"value"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

var details = map[Permission]struct{ label, description string }{
	ReadConsole:        {"Read console", "Open the management console and pick tenants."},
	ReadUsers:          {"Read members", "List the members of a tenant and the roles they hold."},
	ManageApplications: {"Manage applications", "Register applications and configure client credentials."},
	ManageKeys:         {"Manage API keys", "Issue and revoke API keys."},
	ManageContracts:    {"Manage contracts", "Import OpenAPI contracts and their endpoints."},
	ManageUsers:        {"Manage members", "Invite members and change their roles and application grants."},
	ManageRoles:        {"Manage roles", "Create and edit the roles of this tenant."},
	ManageTenants:      {"Manage tenants", "Create tenants and administer the installation."},
	EditProfile:        {"Edit own profile", "Change one's own display name and picture."},
}

// Permissions returns every permission in display order.
func Permissions() []Permission {
	result := make([]Permission, len(ordered))
	copy(result, ordered)
	return result
}

// Parse validates a submitted permission name. Unknown values are rejected so
// that a crafted payload cannot invent capabilities.
func Parse(value string) (Permission, bool) {
	candidate := Permission(value)
	if !known[candidate] {
		return "", false
	}
	return candidate, true
}

// Valid reports whether the value names a permission.
func (p Permission) Valid() bool {
	return known[p]
}

// Catalog returns every permission with a label and description so that the
// console and API clients never hardcode the list.
func Catalog() []Entry {
	result := make([]Entry, 0, len(ordered))
	for _, permission := range ordered {
		detail := details[permission]
		result = append(result, Entry{
			Value:       string(permission),
			Label:       detail.label,
			Description: detail.description,
		})
	}
	return result
}

// Values returns every permission as strings, for use as a SQL array parameter.
func Values() []string {
	result := make([]string, 0, len(ordered))
	for _, permission := range ordered {
		result = append(result, string(permission))
	}
	return result
}
