package authz

import (
	"context"
	"github.com/shrinex/shield/authc"
)

type (
	authorizer struct {
		realms []Realm
	}
)

var (
	_ Authorizer = (*authorizer)(nil)

	// NoopAuthorizer does nothing
	NoopAuthorizer = &authorizer{realms: make([]Realm, 0)}
)

func NewAuthorizer(realm Realm, realms ...Realm) Authorizer {
	return &authorizer{realms: append(realms, realm)}
}

func (z *authorizer) HasRole(ctx context.Context, userDetails authc.UserDetails, role Role) bool {
	for _, r := range z.realms {
		roles, err := r.LoadRoles(ctx, userDetails)
		if err != nil {
			continue
		}

		for _, v := range roles {
			if v.Implies(role) {
				return true
			}
		}
	}

	return false
}

func (z *authorizer) HasAnyRole(ctx context.Context, userDetails authc.UserDetails, roles ...Role) bool {
	for _, role := range roles {
		if z.HasRole(ctx, userDetails, role) {
			return true
		}
	}

	return false
}

func (z *authorizer) HasAllRole(ctx context.Context, userDetails authc.UserDetails, roles ...Role) bool {
	for _, role := range roles {
		if !z.HasRole(ctx, userDetails, role) {
			return false
		}
	}

	return true
}

func (z *authorizer) HasAuthority(ctx context.Context, userDetails authc.UserDetails, authority Authority) bool {
	for _, r := range z.realms {
		authorities, err := r.LoadAuthorities(ctx, userDetails)
		if err != nil {
			continue
		}
		for _, v := range authorities {
			if v.Implies(authority) {
				return true
			}
		}
	}

	return false
}

func (z *authorizer) HasAnyAuthority(ctx context.Context, userDetails authc.UserDetails, authorities ...Authority) bool {
	for _, authority := range authorities {
		if z.HasAuthority(ctx, userDetails, authority) {
			return true
		}
	}

	return false
}

func (z *authorizer) HasAllAuthority(ctx context.Context, userDetails authc.UserDetails, authorities ...Authority) bool {
	for _, authority := range authorities {
		if !z.HasAuthority(ctx, userDetails, authority) {
			return false
		}
	}

	return true
}

func (z *authorizer) Logout(ctx context.Context, userDetails authc.UserDetails) {
	for _, r := range z.realms {
		if la, ok := r.(authc.LogoutAware); ok {
			la.Logout(ctx, userDetails)
		}
	}
}
