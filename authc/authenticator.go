package authc

import (
	"context"
	"errors"
)

type (
	authenticator struct {
		realms []Realm
	}
)

var (
	_ Authenticator = (*authenticator)(nil)

	ErrInvalidToken    = errors.New("invalid token")
	ErrUnauthenticated = errors.New("unauthenticated")
)

func NewAuthenticator(realm Realm, realms ...Realm) Authenticator {
	return &authenticator{realms: append(realms, realm)}
}

func (c *authenticator) Authenticate(ctx context.Context, token Token) (UserDetails, error) {
	if token == nil || len(token.Principal()) == 0 {
		return nil, ErrInvalidToken
	}

	for _, r := range c.realms {
		if r.Supports(token) {
			user, err := r.LoadUserDetails(ctx, token)
			if err != nil {
				if errors.Is(err, ErrUnauthenticated) {
					continue
				}
				return nil, err
			}
			return user, nil
		}
	}

	return nil, ErrUnauthenticated
}

func (c *authenticator) Logout(ctx context.Context, userDetails UserDetails) {
	for _, r := range c.realms {
		if la, ok := r.(LogoutAware); ok {
			la.Logout(ctx, userDetails)
		}
	}
}
