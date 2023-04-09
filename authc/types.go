package authc

import "context"

type (
	Token interface {
		Principal() string
		Credentials() string
		RequiresFullyAuthenticated() bool
	}

	UserDetails interface {
		Principal() string
		Credentials() string
	}

	Realm interface {
		Supports(Token) bool
		LoadUserDetails(context.Context, Token) (UserDetails, error)
	}

	LogoutAware interface {
		Logout(context.Context, string)
	}

	Authenticator interface {
		Authenticate(context.Context, Token) (UserDetails, error)
	}
)
