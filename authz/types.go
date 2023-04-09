package authz

import "context"

type (
	Role interface {
		RawValue() string
		Implies(Role) bool
	}

	Authority interface {
		RawValue() string
		Implies(Authority) bool
	}

	Realm interface {
		LoadRoles(context.Context, string) ([]Role, error)
		LoadAuthorities(context.Context, string) ([]Authority, error)
	}

	Authorizer interface {
		HasRole(context.Context, string, Role) bool
		HasAnyRole(context.Context, string, ...Role) bool
		HasAllRole(context.Context, string, ...Role) bool

		HasAuthority(context.Context, string, Authority) bool
		HasAnyAuthority(context.Context, string, ...Authority) bool
		HasAllAuthority(context.Context, string, ...Authority) bool
	}
)
