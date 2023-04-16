package authc

import "context"

type (
	Token interface {
		Principal() string
		Credentials() string
	}

	UserDetails interface {
		Principal() string
	}

	Realm interface {
		Supports(Token) bool
		LoadUserDetails(context.Context, Token) (UserDetails, error)
	}

	LogoutAware interface {
		Logout(context.Context, UserDetails)
	}

	Authenticator interface {
		Authenticate(context.Context, Token) (UserDetails, error)
	}
)
