package authz

import "context"

type (
	authorizer struct {
		realms []Realm
	}
)

var _ Authorizer = (*authorizer)(nil)

func NewAuthorizer(realm Realm, realms ...Realm) Authorizer {
	return &authorizer{realms: append(realms, realm)}
}

func (z *authorizer) HasRole(ctx context.Context, principal string, role Role) bool {
	for _, r := range z.realms {
		roles, err := r.LoadRoles(ctx, principal)
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

func (z *authorizer) HasAnyRole(ctx context.Context, principal string, roles ...Role) bool {
	for _, role := range roles {
		if z.HasRole(ctx, principal, role) {
			return true
		}
	}

	return false
}

func (z *authorizer) HasAllRole(ctx context.Context, principal string, roles ...Role) bool {
	for _, role := range roles {
		if !z.HasRole(ctx, principal, role) {
			return false
		}
	}

	return true
}

func (z *authorizer) HasAuthority(ctx context.Context, principal string, authority Authority) bool {
	for _, r := range z.realms {
		authorities, err := r.LoadAuthorities(ctx, principal)
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

func (z *authorizer) HasAnyAuthority(ctx context.Context, principal string, authorities ...Authority) bool {
	for _, authority := range authorities {
		if z.HasAuthority(ctx, principal, authority) {
			return true
		}
	}

	return false
}

func (z *authorizer) HasAllAuthority(ctx context.Context, principal string, authorities ...Authority) bool {
	for _, authority := range authorities {
		if !z.HasAuthority(ctx, principal, authority) {
			return false
		}
	}

	return true
}
