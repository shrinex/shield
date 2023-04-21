package authz

import (
	"context"
	"github.com/shrinex/shield/authc"
)

type (
	// Role represents a user role
	Role interface {
		// Desc returns a string description that describe this role
		Desc() string
		// Implies returns true if the specified role is implied by this role
		Implies(Role) bool
	}

	// Authority represents a granted authority
	Authority interface {
		// Desc returns a string description that describe this authority
		Desc() string
		// Implies returns true if the specified authority is implied by this authority
		Implies(Authority) bool
	}

	// A Realm is responsible for loading Role(s) and Authority(s)
	Realm interface {
		// LoadRoles returns all Role(s) belong to the specified authc.UserDetails
		LoadRoles(context.Context, authc.UserDetails) ([]Role, error)
		// LoadAuthorities returns all Authority(s) belong to the specified authc.UserDetails
		LoadAuthorities(context.Context, authc.UserDetails) ([]Authority, error)
	}

	// An Authorizer performs authorization (access control) operations for any given user
	Authorizer interface {
		// HasRole specifies a user requires an role
		HasRole(context.Context, authc.UserDetails, Role) bool
		// HasAnyRole specifies that a user requires one of many role
		HasAnyRole(context.Context, authc.UserDetails, ...Role) bool
		// HasAllRole specifies that a user requires all of roles
		HasAllRole(context.Context, authc.UserDetails, ...Role) bool

		// HasAuthority specifies a user requires an authority
		HasAuthority(context.Context, authc.UserDetails, Authority) bool
		// HasAnyAuthority specifies that a user requires one of many authorities
		HasAnyAuthority(context.Context, authc.UserDetails, ...Authority) bool
		// HasAllAuthority specifies that a user requires all of authorities
		HasAllAuthority(context.Context, authc.UserDetails, ...Authority) bool
	}
)
