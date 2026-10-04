// Package role defines the tenant membership roles and the single permission
// matrix that authorizes console and management behavior.
//
// Roles are stored in memberships.role. Authorization decisions must derive
// from Grants or Allows so that SQL role checks and Go checks cannot drift
// apart.
package role

// Role is a tenant membership role.
type Role string

const (
	// Owner has full control of a tenant, including tenant-level settings.
	Owner Role = "owner"
	// Admin manages applications, credentials, contracts, and members.
	Admin Role = "admin"
	// Developer manages applications, credentials, and contracts.
	Developer Role = "developer"
	// Operator issues and revokes credentials and imports contracts.
	Operator Role = "operator"
	// Viewer reads the console without changing anything.
	Viewer Role = "viewer"
	// User is a self-service member. It carries no console access and exists so
	// that end users of client applications still hold a tenant role that
	// applications can read through /connect/userinfo.
	User Role = "user"
)

// Permission is a capability granted by a role.
type Permission string

const (
	ReadConsole        Permission = "console.read"
	ReadUsers          Permission = "users.read"
	ManageApplications Permission = "applications.manage"
	ManageKeys         Permission = "keys.manage"
	ManageContracts    Permission = "contracts.manage"
	ManageUsers        Permission = "users.manage"
	ManageTenants      Permission = "tenants.manage"
	EditProfile        Permission = "profile.edit"
)

// catalog lists every role in descending order of privilege.
var catalog = []Role{Owner, Admin, Developer, Operator, Viewer, User}

// grants is the permission matrix. ReadConsole is deliberately absent for User
// so that self-service members are routed to the profile screen instead of the
// management console.
var grants = map[Role]map[Permission]bool{
	Owner: {
		ReadConsole: true, ReadUsers: true, ManageApplications: true, ManageKeys: true,
		ManageContracts: true, ManageUsers: true, ManageTenants: true, EditProfile: true,
	},
	Admin: {
		ReadConsole: true, ReadUsers: true, ManageApplications: true, ManageKeys: true,
		ManageContracts: true, ManageUsers: true, EditProfile: true,
	},
	Developer: {
		ReadConsole: true, ReadUsers: true, ManageApplications: true, ManageKeys: true,
		ManageContracts: true, EditProfile: true,
	},
	Operator: {
		ReadConsole: true, ReadUsers: true, ManageKeys: true, ManageContracts: true, EditProfile: true,
	},
	Viewer: {
		ReadConsole: true, ReadUsers: true, EditProfile: true,
	},
	User: {
		EditProfile: true,
	},
}

var ordered = []Permission{
	ReadConsole, ReadUsers, ManageApplications, ManageKeys,
	ManageContracts, ManageUsers, ManageTenants, EditProfile,
}

// Entry describes a role for the console and for API clients.
type Entry struct {
	Value       string   `json:"value"`
	Label       string   `json:"label"`
	Permissions []string `json:"permissions"`
}

var labels = map[Role]string{
	Owner:     "Owner",
	Admin:     "Administrator",
	Developer: "Developer",
	Operator:  "Operator",
	Viewer:    "Viewer",
	User:      "User",
}

// All returns every role ordered from most to least privileged.
func All() []Role {
	result := make([]Role, len(catalog))
	copy(result, catalog)
	return result
}

// Catalog returns every role with its label and permissions so that the console
// and API clients never hardcode the role list.
func Catalog() []Entry {
	result := make([]Entry, 0, len(catalog))
	for _, item := range catalog {
		result = append(result, Entry{Value: string(item), Label: labels[item], Permissions: item.Permissions()})
	}
	return result
}

// Parse converts a stored or submitted value into a Role.
func Parse(value string) (Role, bool) {
	candidate := Role(value)
	if _, known := grants[candidate]; !known {
		return "", false
	}
	return candidate, true
}

// Valid reports whether the value names a role.
func (r Role) Valid() bool {
	_, known := grants[r]
	return known
}

// Allows reports whether the role grants the permission.
func (r Role) Allows(permission Permission) bool {
	return grants[r][permission]
}

// Permissions returns the role's permissions in a stable order.
func (r Role) Permissions() []string {
	result := make([]string, 0, len(ordered))
	for _, permission := range ordered {
		if r.Allows(permission) {
			result = append(result, string(permission))
		}
	}
	return result
}

// Grants returns the roles that grant a permission, for use as a SQL parameter
// so that role checks in queries stay aligned with this matrix.
func Grants(permission Permission) []string {
	result := make([]string, 0, len(catalog))
	for _, item := range catalog {
		if item.Allows(permission) {
			result = append(result, string(item))
		}
	}
	return result
}

// Grantable returns the roles a tenant administrator may hand to a new member.
// Ownership is not grantable during an invitation because it is established by
// creating or claiming a tenant.
func Grantable() []Role {
	result := make([]Role, 0, len(catalog)-1)
	for _, item := range catalog {
		if item != Owner {
			result = append(result, item)
		}
	}
	return result
}

// GrantableValues returns Grantable as strings for a request payload.
func GrantableValues() []string {
	values := Grantable()
	result := make([]string, len(values))
	for index, item := range values {
		result[index] = string(item)
	}
	return result
}
