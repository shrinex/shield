package authz

import (
	"context"
	"github.com/shrinex/shield/authc"
)

type (
	Role interface {
		Desc() string
		Implies(Role) bool
	}

	Authority interface {
		Desc() string
		Implies(Authority) bool
	}

	Realm interface {
		LoadRoles(context.Context, authc.UserDetails) ([]Role, error)
		LoadAuthorities(context.Context, authc.UserDetails) ([]Authority, error)
	}

	Authorizer interface {
		HasRole(context.Context, authc.UserDetails, Role) bool
		HasAnyRole(context.Context, authc.UserDetails, ...Role) bool
		HasAllRole(context.Context, authc.UserDetails, ...Role) bool

		HasAuthority(context.Context, authc.UserDetails, Authority) bool
		HasAnyAuthority(context.Context, authc.UserDetails, ...Authority) bool
		HasAllAuthority(context.Context, authc.UserDetails, ...Authority) bool
	}
)
